package manyfactorstore

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

var getPin = getPinTerm

func getPinTerm() (string, error) {
	if os.Getenv("AGE_PLUGIN_MANYFACTORSTORE_PIN") != "" {
		return os.Getenv("AGE_PLUGIN_MANYFACTORSTORE_PIN"), nil
	}

	fmt.Fprintf(os.Stderr, "Enter the security key PIN: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Printf("Error reading the PIN: %s\n", err)
		return "", err
	}
	fmt.Fprintf(os.Stderr, "\r\033[K") // Clear the line.
	return string(pin), nil
}

func getPinAgePlugin() (string, error) {
	if os.Getenv("AGE_PLUGIN_MANYFACTORSTORE_PIN") != "" {
		return os.Getenv("AGE_PLUGIN_MANYFACTORSTORE_PIN"), nil
	}
	return plugin_state.RequestValue("Enter the security key PIN:", true)
}
