package manyfactorstore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/fxamacker/cbor"
	"github.com/keys-pub/go-libfido2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const ManyFactorStoreID = "manyfactorstore-t6uh9av7whdoa00qwl18w3ggab6pycd1h8v3"

func NewCredential(rpID, name, option string) (string, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return "", err
	}
	if len(locs) == 0 {
		return "", errors.New("no FIDO2 devices found")
	}
	if len(locs) != 1 {
		return "", errors.New("multiple FIDO2 devices found, please remove all but one")
	}

	options, err := ParseOptions(option)
	if err != nil {
		return "", err
	}

	_ = options

	pinRequired := options.VerifyPIN
	var pin string
	if pinRequired {
		pin, err = getPin()
		if err != nil {
			return "", err
		}
	}

	device, err := libfido2.NewDevice(locs[0].Path)
	if err != nil {
		return "", err
	}

	mkOpt_UV := libfido2.False
	if pinRequired {
		mkOpt_UV = libfido2.True
	}

	a, err := device.MakeCredential(
		// The client data hash is not useful without attestation.
		bytes.Repeat([]byte{0}, 32),
		libfido2.RelyingParty{ID: rpID},
		libfido2.User{
			// These are not used for non-resident credentials,
			// but the Go wrapper requires them.
			ID:   []byte{0},
			Name: name,
			//DisplayName: name,
		},
		libfido2.ES256,
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			RK:         libfido2.False,
			UV:         mkOpt_UV,
		})
	if err != nil {
		return "", err
	}
	identity := &IdentityStructure{
		Version:         1,
		Options:         option,
		Name:            name,
		RelayingPartyID: rpID,
		IdentityID:      a.CredentialID,
	}
	var buf bytes.Buffer
	encoder := cbor.NewEncoder(&buf, cbor.CanonicalEncOptions())
	if err := encoder.Encode(identity); err != nil {
		return "", err
	}
	return plugin.EncodeIdentity(ManyFactorStoreID, buf.Bytes()), nil
}

const label = "age-encryption.org/" + ManyFactorStoreID

const defaultPassword = label + "-default"

func (i *IdentityStructure) assert(nonce []byte, options *Options) ([]byte, error) {

	var err error

	shouldTouch := options.Touch

	pinRequired := options.VerifyPIN

	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, err
	}
	if len(locs) == 0 {
		return nil, errors.New("no FIDO2 devices found")
	}
	for _, loc := range locs {
		device, err := libfido2.NewDevice(loc.Path)
		if err != nil {
			return nil, err
		}

		// First probe to check if the credential ID matches the device,
		// before requiring user interaction.
		if _, err := device.Assertion(
			i.RelayingPartyID,
			make([]byte, 32),
			[][]byte{i.IdentityID},
			"",
			&libfido2.AssertionOpts{
				UP: libfido2.False,
			},
		); errors.Is(err, libfido2.ErrNoCredentials) {
			continue
		} else if err != nil {
			return nil, err
		}

		assertionUP := libfido2.False
		if shouldTouch {
			assertionUP = libfido2.True
		}

		var pin string
		if pinRequired {
			pin, err = getPin()
			if err != nil {
				return nil, err
			}
		}

		assertionUV := libfido2.False
		if pinRequired {
			assertionUV = libfido2.True
		}

		assertion, err := device.Assertion(
			i.RelayingPartyID,
			make([]byte, 32),
			[][]byte{i.IdentityID},
			pin,
			&libfido2.AssertionOpts{
				Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
				HMACSalt:   hmacSecretSalt(nonce),
				UV:         assertionUV,
				UP:         assertionUP,
			},
		)
		if err != nil {
			return nil, err
		}

		if assertion.HMACSecret == nil {
			return nil, errors.New("FIDO2 device doesn't support HMACSecret extension")
		}
		return assertion.HMACSecret, nil
	}

	return nil, errors.New("identity doesn't match any FIDO2 device")
}

func hmacSecretSalt(nonce []byte) []byte {
	// The PRF inputs for age-encryption.org/fido2prf are
	//
	//   "age-encryption.org/fido2prf" || 0x01 || nonce
	//
	// and
	//
	//   "age-encryption.org/fido2prf" || 0x02 || nonce
	//
	// The WebAuthn PRF inputs are then hashed into FIDO2 hmac-secret salts.
	//
	//   SHA-256("WebAuthn PRF" || 0x00 || input)
	//
	h := sha256.New()
	h.Write([]byte("WebAuthn PRF"))
	h.Write([]byte{0})
	h.Write([]byte(label))
	h.Write([]byte{1})
	h.Write(nonce)
	salt := h.Sum(nil)
	h.Reset()
	h.Write([]byte("WebAuthn PRF"))
	h.Write([]byte{0})
	h.Write([]byte(label))
	h.Write([]byte{2})
	h.Write(nonce)
	return h.Sum(salt)
}

func (i *IdentityStructure) Unwrap(s []*age.Stanza) ([]byte, error) {
	options, err := ParseOptions(i.Options)
	if err != nil {
		return nil, err
	}

	_ = options

	// Get password if it is required.
	password := defaultPassword
	if options.VerifyPassword {
		passwordRecv, err := plugin_state.RequestValue("Password:", true)
		if err != nil {
			return nil, err
		}
		if passwordRecv == "" {
			return nil, errors.New("password required")
		}
		password = passwordRecv
	}

	for _, stanza := range s {
		if stanza.Type != label {
			continue
		}
		if len(stanza.Args) != 1 {
			return nil, errors.New("fido2prf: invalid stanza: expected 1 argument")
		}
		nonce, err := base64.RawStdEncoding.Strict().DecodeString(stanza.Args[0])
		if err != nil || len(nonce) != 16 {
			return nil, errors.New("fido2prf: invalid nonce")
		}

		secret__nonce_password := hkdf.Extract(sha256.New, nonce, []byte(password))

		secret__nonce_password_securitykey, err := i.assert(secret__nonce_password, options)
		if err != nil {
			return nil, err
		}

		secret__nonce_password_securitykey_password := hkdf.Extract(sha256.New, secret__nonce_password_securitykey, []byte(password))

		key := hkdf.Extract(sha256.New, secret__nonce_password_securitykey_password, []byte(label))
		fileKey, err := aeadDecrypt(key, 16, stanza.Body)
		if err != nil {
			continue
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}

func (i *IdentityStructure) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	options, err := ParseOptions(i.Options)
	if err != nil {
		return nil, err
	}

	_ = options

	// Get password if it is required.
	password := defaultPassword
	if options.VerifyPassword {
		passwordRecv, err := plugin_state.RequestValue("Password:", true)
		if err != nil {
			return nil, err
		}
		if passwordRecv == "" {
			return nil, errors.New("password required")
		}
		password = passwordRecv
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	secret__nonce_password := hkdf.Extract(sha256.New, nonce, []byte(password))

	secret__nonce_password_securitykey, err := i.assert(secret__nonce_password, options)
	if err != nil {
		return nil, err
	}

	secret__nonce_password_securitykey_password := hkdf.Extract(sha256.New, secret__nonce_password_securitykey, []byte(password))

	key := hkdf.Extract(sha256.New, secret__nonce_password_securitykey_password, []byte(label))
	ciphertext, err := aeadEncrypt(key, fileKey)
	if err != nil {
		return nil, err
	}
	return []*age.Stanza{{
		Type: label,
		Args: []string{base64.RawStdEncoding.Strict().EncodeToString(nonce)},
		Body: ciphertext,
	}}, nil
}

func NewIdentity(s string) (*IdentityStructure, error) {
	name, data, err := plugin.ParseIdentity(s)
	if err != nil {
		return nil, err
	}
	if name != ManyFactorStoreID {
		return nil, errors.New("not a many factor store identity")
	}
	return NewIdentityFromData(data)
}

func NewIdentityFromData(data []byte) (*IdentityStructure, error) {
	i := &IdentityStructure{}
	decoder := cbor.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(i)
	if err != nil {
		return nil, err
	}
	return i, nil
}

func aeadDecrypt(key []byte, size int, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) != size+aead.Overhead() {
		return nil, errors.New("encrypted value has unexpected length")
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Open(nil, nonce, ciphertext, nil)
}

func aeadEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, plaintext, nil), nil
}
