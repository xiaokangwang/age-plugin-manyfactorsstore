package main

import (
	"flag"
	"fmt"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/xiaokangwang/age-plugin-manyfactorsstore/pkg/manyfactorstore"
)

func main() {
	p, err := plugin.New(manyfactorstore.ManyFactorStoreID)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	generate := flag.String("generate", "", "Generate a new credential for the given relying party ID.")
	name := flag.String("name", "", "Generate: the name of the credential.")
	option := flag.String("options", "", "Generate: options for the given key.")
	p.RegisterFlags(nil)
	flag.Parse()
	if *generate != "" {

		identity, err := manyfactorstore.NewCredential(*generate, *name, *option)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			os.Exit(1)
		}
		fmt.Println(identity)
		return
	}

	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		identity, err := manyfactorstore.NewIdentityFromData(data)
		if err != nil {
			return nil, err
		}

		return manyfactorstore.NewIdentityWrapper(identity, identity, p), nil
	})
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		identity, err := manyfactorstore.NewIdentityFromData(data)
		if err != nil {
			return nil, err
		}

		return manyfactorstore.NewIdentityWrapper(identity, identity, p), nil
	})
	os.Exit(p.Main())
}
