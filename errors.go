package keygloak

import "fmt"

func envNotSet(name string) error {
	return fmt.Errorf("environment variable '%s' is not set", name)
}
