package e2e

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/DunkelCloud/ergosum/internal/admin"
	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

func adminSigner(s ssh.Signer) admin.Signer {
	return func(_ context.Context, canonical []byte) ([]byte, error) {
		return sshsig.Sign(s, journal.Namespace, canonical)
	}
}

// TestFourEyes walks the administrator flow with approvals 2: the tool
// reads the current epoch, two administrators sign separately, the first
// signature alone is refused, the merged event is recorded and reaches the
// other instance; a revocation follows at the next epoch.
func TestFourEyes(t *testing.T) {
	c := newCluster(t, []string{instA, instB}, clusterOptions{threshold: 2})
	a, b := c.envs[instA], c.envs[instB]
	ctx := context.Background()
	// The first authority is down; the tool moves on to the next.
	client, err := admin.NewClient(admin.Config{TrustDomain: trustDomain, Authorities: []admin.Authority{
		{URL: "https://" + freePort(t), Key: a.fingerprint()},
		{URL: a.url, Key: a.fingerprint()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	fp := fingerprintOf(t)
	e, cur, err := admin.NewEvent(ctx, client, journal.KindBindingSet, trustDomain, host1, 0, fp, []journal.Check{tailnetCheck(host1Tailnet)})
	if err != nil || cur != nil || e.Epoch != 1 {
		t.Fatalf("new event: %+v, current %+v, %v", e, cur, err)
	}
	alice, bob := *e, *e
	if _, err := admin.AddSignature(ctx, &alice, adminSigner(c.admins.Signers["alice"])); err != nil {
		t.Fatal(err)
	}
	var se *admin.SubmitError
	if _, _, err := client.Submit(ctx, &alice); !errors.As(err, &se) || se.Status != http.StatusUnprocessableEntity {
		t.Fatalf("one approval of two: %v", err)
	}
	if _, err := admin.AddSignature(ctx, &bob, adminSigner(c.admins.Signers["bob"])); err != nil {
		t.Fatal(err)
	}
	merged, err := admin.Merge(&alice, &bob)
	if err != nil {
		t.Fatal(err)
	}
	r, from, err := client.Submit(ctx, merged)
	if err != nil || from != a.url || r.Origin != instA {
		t.Fatalf("submit: %+v from %s: %v", r, from, err)
	}
	eventually(t, "binding at B", func() bool { return b.binding(host1) != nil })

	rev, cur, err := admin.NewEvent(ctx, client, journal.KindBindingRevoked, trustDomain, host1, 0, "", nil)
	if err != nil || cur == nil || rev.Epoch != 2 {
		t.Fatalf("revocation: %+v, current %+v, %v", rev, cur, err)
	}
	for _, n := range []string{"carol", "alice"} {
		if _, err := admin.AddSignature(ctx, rev, adminSigner(c.admins.Signers[n])); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := client.Submit(ctx, rev); err != nil {
		t.Fatal(err)
	}
	eventually(t, "revocation at B", func() bool { bd := b.binding(host1); return bd != nil && !bd.Active() })
}
