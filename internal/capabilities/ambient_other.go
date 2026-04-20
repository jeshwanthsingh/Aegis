//go:build !linux

package capabilities

func RaiseAmbient(_ []string) error {
	return nil
}
