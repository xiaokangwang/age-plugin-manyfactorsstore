package manyfactorstore

import (
	"errors"
	"strings"
)

type Options struct {
	// option: touch
	Touch bool
	// option: pin
	VerifyPIN bool
	// option: password
	VerifyPassword bool
}

func ParseOptions(option string) (*Options, error) {
	opts := &Options{}
	if option == "" {
		return opts, nil
	}
	for _, o := range strings.Split(option, ",") {
		switch o {
		case "touch":
			opts.Touch = true
		case "password":
			opts.VerifyPassword = true
		case "pin":
			opts.VerifyPIN = true
		default:
			return nil, errors.New("fido2prf: invalid option: " + o)
		}
	}
	return opts, nil
}
