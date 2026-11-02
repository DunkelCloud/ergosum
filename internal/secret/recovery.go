package secret

import (
	"bytes"
	"fmt"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
)

// Recovery encrypts the secret with age to the recipients, X25519
// ("age1...") or "ssh-ed25519 ..." public keys, ASCII-armored: the way
// back when no instance can be reached. An administrator opens it with
// the stock age tool and the private key. No recipients: no recovery.
func Recovery(plain []byte, recipients []string) (string, error) {
	if len(recipients) == 0 {
		return "", nil
	}
	rs := make([]age.Recipient, 0, len(recipients))
	for _, s := range recipients {
		s = strings.TrimSpace(s)
		var r age.Recipient
		var err error
		switch {
		case strings.HasPrefix(s, "age1"):
			r, err = age.ParseX25519Recipient(s)
		case strings.HasPrefix(s, "ssh-ed25519 "):
			r, err = agessh.ParseRecipient(s)
		default:
			err = fmt.Errorf("neither an age X25519 nor an ssh-ed25519 public key")
		}
		if err != nil {
			return "", fmt.Errorf("recovery recipient %q: %w", clip(s), err)
		}
		rs = append(rs, r)
	}
	var b bytes.Buffer
	aw := armor.NewWriter(&b)
	w, err := age.Encrypt(aw, rs...)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(plain); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := aw.Close(); err != nil {
		return "", err
	}
	return b.String(), nil
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
