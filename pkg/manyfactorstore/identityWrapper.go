package manyfactorstore

import (
	"filippo.io/age"
	"filippo.io/age/plugin"
)

var plugin_state *plugin.Plugin

type identityWrapper struct {
	age.Identity
	age.Recipient
}

type symIdentity interface {
	age.Identity
	age.Recipient
}

func NewIdentityWrapper(id age.Identity, rec age.Recipient, pluginState *plugin.Plugin) *identityWrapper {
	plugin_state = pluginState
	getPin = getPinAgePlugin
	return &identityWrapper{
		Identity:  id,
		Recipient: rec,
	}
}

func (w *identityWrapper) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	fk, err := w.Identity.Unwrap(stanzas)
	if err != nil {
		plugin_state.DisplayMessage(err.Error())
		return nil, err
	}
	return fk, nil
}

func (w *identityWrapper) Wrap(fileKey []byte) (stanzas []*age.Stanza, err error) {
	s, err := w.Recipient.Wrap(fileKey)
	if err != nil {
		plugin_state.DisplayMessage(err.Error())
		return nil, err
	}
	return s, nil
}
