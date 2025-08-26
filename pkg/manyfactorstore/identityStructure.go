package manyfactorstore

type IdentityStructure struct {
	Version         int32
	Options         string
	Name            string
	RelayingPartyID string
	IdentityID      []byte
}
