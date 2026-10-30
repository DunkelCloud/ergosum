package admin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

// Tool carries out the administrator commands: bind, revoke, show and list.
// It talks to the administrator through Out and Confirm, and to the
// authorities through Client.
type Tool struct {
	Client *Client
	// Key signs; nil if no key is configured.
	Key *SignKey
	// TrustDomain, if set, must be the authorities' trust domain.
	TrustDomain string
	// Out receives what the administrator reads.
	Out io.Writer
	// Confirm asks before signing; nil signs without asking.
	Confirm func(question string) error
	// Now defaults to time.Now.
	Now func() time.Time
}

// ErrEpochMoved is returned when the binding changed between making a file
// and recording it: the file must be made anew, so that no change replaces
// another one unnoticed.
var ErrEpochMoved = errors.New("the binding changed since this file was made")

func (t *Tool) now() string {
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	return now().UTC().Format(time.RFC3339)
}

func (t *Tool) printf(format string, a ...any) { _, _ = fmt.Fprintf(t.Out, format, a...) }

// Bind takes the binding file at path one step further: it adds kind, trust
// domain and epoch, shows the text to sign and how it differs from the
// current binding, signs with the administrator's key, and records the
// event once the approvals reach the threshold. A second administrator
// runs the same command on the same file.
func (t *Tool) Bind(ctx context.Context, path string) error {
	return t.bind(ctx, path, "")
}

// Text completes the binding file at path like Bind and writes the text to
// sign to out (LF line endings), for signing with "ssh-keygen -Y sign" by
// hand; the signature goes back into the file.
func (t *Tool) Text(ctx context.Context, path, out string) error {
	return t.bind(ctx, path, out)
}

func (t *Tool) bind(ctx context.Context, path, textOut string) error {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return err
	}
	f, err := ParseFile(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	list, from, err := t.Client.List(ctx)
	if err != nil {
		return err
	}
	cur := find(list, f.Identity)
	added, err := t.complete(f, list, from, cur)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	e := f.Event()
	canonical, err := e.Canonical()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	hash, _ := e.Hash()
	if cur != nil && cur.Hash == hash {
		t.printf("%s: recorded already at epoch %d (%s/%d).\n", e.Identity, cur.Epoch, cur.Origin, cur.Seq)
		return nil
	}
	if err := checkEpoch(f, cur, from); err != nil {
		return err
	}
	ap, ok := list.Approvals[e.Kind]
	if !ok {
		return fmt.Errorf("%s names no approvals for %s", from, e.Kind)
	}
	names := map[string]string{} // fingerprint -> administrator
	for name, fp := range ap.Admins {
		names[fp] = name
	}
	signed, err := checkSignatures(e.Signatures, canonical, e.Kind, ap, names)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if textOut != "" {
		if err := t.write(path, f, added); err != nil {
			return err
		}
		if err := keys.WriteFileAtomic(textOut, canonical, 0o644); err != nil { //nolint:gosec // no secret
			return err
		}
		t.printf("The text to sign is in %s. Sign it and append the signature to %s:\n"+
			"    ssh-keygen -Y sign -f KEY -n %s %s\n", textOut, path, journal.Namespace, textOut)
		return nil
	}

	// The text to sign comes last, right before the question.
	t.describe(e, cur)
	t.printf("\nApprovals for %s: %d of %d%s. Allowed: %s.\n", e.Kind, len(signed), ap.Threshold, nameList(signed), strings.Join(sortedKeys(ap.Admins), ", "))
	t.printf("\nText to sign:\n%s", indent(canonical))

	if len(signed) < ap.Threshold {
		done, err := t.sign(ctx, path, f, e, added, names, signed)
		if err != nil || done {
			return err
		}
		signed = append(signed, names[lastSigner(e)])
		added = nil
		if len(signed) < ap.Threshold {
			t.printf("\n%d of %d approvals. Pass %s to another administrator, who runs:\n    ergosum bind %s\n", len(signed), ap.Threshold, path, path)
			return nil
		}
	}
	if err := t.write(path, f, added); err != nil {
		return err
	}
	r, at, err := t.Client.Submit(ctx, e)
	var se *SubmitError
	if errors.As(err, &se) && se.Status == http.StatusConflict {
		return fmt.Errorf("%w: %s refused it (%s). %s", ErrEpochMoved, se.Authority, se.Detail, startAgain(e.Identity))
	}
	if err != nil {
		return err
	}
	f.Append(fmt.Sprintf("# recorded by %s as %s/%d at %s", at, r.Origin, r.Seq, t.now()))
	if err := t.write(path, f, nil); err != nil {
		return err
	}
	t.printf("\nRecorded by %s as %s/%d.\n", at, r.Origin, r.Seq)
	t.next(e, cur, list.TrustDomain)
	return nil
}

// sign adds the administrator's signature. done reports that there was
// nothing to sign.
func (t *Tool) sign(ctx context.Context, path string, f *File, e *journal.BindingEvent, added []string, names map[string]string, signed []string) (done bool, err error) {
	if t.Key == nil {
		return false, fmt.Errorf("no key to sign with: set sign_key in the configuration or give -sign-key")
	}
	who := "the configured key"
	if fp := t.Key.Fingerprint(); fp != "" {
		name, allowed := names[fp]
		if !allowed {
			return false, fmt.Errorf("your key %s may not approve %s", fp, e.Kind)
		}
		if slices.Contains(signed, name) {
			t.printf("\nYou (%s) have signed already. Pass %s to another administrator, who runs:\n    ergosum bind %s\n", name, path, path)
			return true, nil
		}
		who = name + " (" + fp + ")"
	}
	if t.Confirm != nil {
		if err := t.Confirm("Sign as " + who + "?"); err != nil {
			return false, err
		}
	}
	fp, err := AddSignature(ctx, e, t.Key.Sign)
	if errors.Is(err, ErrAlreadySigned) {
		t.printf("\n%s has signed already. Pass %s to another administrator.\n", fp, path)
		return true, nil
	}
	if err != nil {
		return false, err
	}
	name, allowed := names[fp]
	if !allowed {
		return false, fmt.Errorf("the key %s signed, but it may not approve %s; nothing written", fp, e.Kind)
	}
	sig := e.Signatures[len(e.Signatures)-1]
	lines := append(append([]string{}, added...), fmt.Sprintf("# signed by %s (%s) at %s", name, fp, t.now()))
	f.Append(append(lines, strings.Split(strings.TrimRight(sig, "\n"), "\n")...)...)
	f.Signatures = append(f.Signatures, sig)
	if err := t.write(path, f, nil); err != nil {
		return false, err
	}
	t.printf("Signed by %s; the signature is in %s.\n", name, path)
	return false, nil
}

func lastSigner(e *journal.BindingEvent) string {
	pub, _, err := sshsig.Inspect([]byte(e.Signatures[len(e.Signatures)-1]))
	if err != nil {
		return ""
	}
	return sshsig.Fingerprint(pub)
}

func (t *Tool) write(path string, f *File, added []string) error {
	if len(added) > 0 {
		f.Append(added...)
	}
	return keys.WriteFileAtomic(path, f.Bytes(), 0o644) //nolint:gosec // holds no secret
}

func find(l *journal.BindingList, identity string) *journal.Binding {
	for _, b := range l.Bindings {
		if b.Identity == identity {
			return b
		}
	}
	return nil
}

// complete fills in what the administrator side knows: the kind (a binding
// unless the file says otherwise), the trust domain and the next epoch. It
// returns the lines to add to the file.
func (t *Tool) complete(f *File, l *journal.BindingList, from string, cur *journal.Binding) ([]string, error) {
	if t.TrustDomain != "" && t.TrustDomain != l.TrustDomain {
		return nil, fmt.Errorf("the configured trust domain %s differs from %s at %s", t.TrustDomain, l.TrustDomain, from)
	}
	var add []string
	if f.Kind == "" {
		if f.Key == "" {
			return nil, errors.New(`no key line: a binding names the machine's key, as "ergosumd request" writes it`)
		}
		f.Kind = journal.KindBindingSet
		add = append(add, "kind "+f.Kind)
	}
	switch {
	case f.TrustDomain == "":
		f.TrustDomain = l.TrustDomain
		add = append(add, "trust-domain "+f.TrustDomain)
	case f.TrustDomain != l.TrustDomain:
		return nil, fmt.Errorf("the file is for trust domain %s, %s serves %s", f.TrustDomain, from, l.TrustDomain)
	}
	if f.Epoch == 0 {
		f.Epoch = 1
		if cur != nil {
			f.Epoch = cur.Epoch + 1
		}
		add = append(add, fmt.Sprintf("epoch %d", f.Epoch))
	}
	if add != nil {
		add = append([]string{"# added by ergosum bind at " + t.now() + ", epoch from " + from}, add...)
	}
	return add, nil
}

// checkEpoch insists on the epoch after the current one.
func checkEpoch(f *File, cur *journal.Binding, from string) error {
	next := uint64(1)
	if cur != nil {
		next = cur.Epoch + 1
	}
	switch {
	case f.Epoch == next:
		return nil
	case f.Epoch < next:
		return fmt.Errorf("%w: %s is at epoch %d now (%s), the file is for epoch %d. %s",
			ErrEpochMoved, f.Identity, cur.Epoch, describe(cur), f.Epoch, startAgain(f.Identity))
	default:
		return fmt.Errorf("the file is for epoch %d, but %s has %s only at epoch %d: it has not received the latest change yet (try again shortly), or the epoch line was edited",
			f.Epoch, from, f.Identity, next-1)
	}
}

func startAgain(identity string) string {
	return fmt.Sprintf("Start with a new file: \"ergosumd request\" on the machine, or \"ergosum show %s\", and bind that.", identity)
}

// checkSignatures verifies every signature over the canonical text and
// explains the usual mistakes. It returns the names of the signers.
func checkSignatures(sigs []string, canonical []byte, kind string, ap journal.Approval, names map[string]string) ([]string, error) {
	var out []string
	for i, s := range sigs {
		n := i + 1
		pub, err := sshsig.Verify([]byte(s), journal.Namespace, canonical)
		if err != nil {
			return nil, explainSignature(n, []byte(s), canonical, err)
		}
		fp := sshsig.Fingerprint(pub)
		name, ok := names[fp]
		if !ok {
			return nil, fmt.Errorf("signature %d is by %s, which may not approve %s (allowed: %s); remove it", n, fp, kind, strings.Join(sortedKeys(ap.Admins), ", "))
		}
		if slices.Contains(out, name) {
			return nil, fmt.Errorf("signature %d repeats the signature of %s; remove it", n, name)
		}
		out = append(out, name)
	}
	return out, nil
}

func explainSignature(n int, sig, canonical []byte, err error) error {
	pub, ns, perr := sshsig.Inspect(sig)
	if perr != nil {
		return fmt.Errorf("signature %d is not an SSH signature (%w): paste the whole .sig file, from BEGIN to END", n, perr)
	}
	who := sshsig.Fingerprint(pub)
	if errors.Is(err, sshsig.ErrNamespace) {
		return fmt.Errorf("signature %d (%s) was made for namespace %q: sign with -n %s", n, who, ns, journal.Namespace)
	}
	crlf := bytes.ReplaceAll(canonical, []byte("\n"), []byte("\r\n"))
	if _, cerr := sshsig.Verify(sig, journal.Namespace, crlf); cerr == nil {
		return fmt.Errorf("signature %d (%s) was made over the text with CRLF line endings, as an editor on Windows saves it: "+
			"sign the file that \"ergosum bind -text OUT FILE\" writes, unchanged, and replace the signature", n, who)
	}
	if errors.Is(err, sshsig.ErrBadSignature) {
		return fmt.Errorf("signature %d (%s) does not match the text: the text was changed after it was signed. "+
			"Undo the change, or remove the signature and sign the new text", n, who)
	}
	return fmt.Errorf("signature %d (%s): %w", n, who, err)
}

// describe summarizes a binding in one line.
func describe(b *journal.Binding) string {
	if !b.Active() {
		return "revoked"
	}
	return "key " + b.Key + ", " + checksText(b.Checks)
}

func checksText(cs []journal.Check) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, c.Type+" "+c.Target)
	}
	return strings.Join(parts, ", ")
}

// describe shows what the event changes.
func (t *Tool) describe(e *journal.BindingEvent, cur *journal.Binding) {
	switch {
	case e.Kind == journal.KindBindingRevoked && cur.Active():
		t.printf("\nRevoke %s at epoch %d. It ends the binding of epoch %d:\n    key %s\n", e.Identity, e.Epoch, cur.Epoch, cur.Key)
		for _, c := range cur.Checks {
			t.printf("    %s\n", CheckLine(c))
		}
	case e.Kind == journal.KindBindingRevoked:
		t.printf("\nRevoke %s at epoch %d.\n", e.Identity, e.Epoch)
	case cur == nil:
		t.printf("\nBind %s for the first time, at epoch %d:\n", e.Identity, e.Epoch)
	case !cur.Active():
		t.printf("\nBind %s again: revoked in epoch %d, this binding takes epoch %d:\n", e.Identity, cur.Epoch, e.Epoch)
	default:
		t.printf("\nChange the binding of %s, epoch %d -> %d:\n", e.Identity, cur.Epoch, e.Epoch)
	}
	if e.Kind == journal.KindBindingSet {
		active := cur.Active()
		switch {
		case active && cur.Key != e.Key:
			t.printf("    key %s -> %s (new key)\n", cur.Key, e.Key)
		case active:
			t.printf("    key %s (unchanged)\n", e.Key)
		default:
			t.printf("    key %s\n", e.Key)
		}
		old := map[journal.Check]bool{}
		if active {
			for _, c := range cur.Checks {
				old[c] = true
			}
		}
		for _, c := range e.SortedChecks() {
			mark := " "
			if active && !old[c] {
				mark = "+"
			}
			delete(old, c)
			t.printf("  %s %s\n", mark, CheckLine(c))
		}
		gone := &journal.BindingEvent{}
		for c := range old {
			gone.Checks = append(gone.Checks, c)
		}
		for _, c := range gone.SortedChecks() {
			t.printf("  - %s\n", CheckLine(c))
		}
	}
}

// next tells the administrator what follows a recorded event.
func (t *Tool) next(e *journal.BindingEvent, cur *journal.Binding, trustDomain string) {
	switch {
	case e.Kind == journal.KindBindingRevoked:
		alias := "spiffe://" + trustDomain + "/host/" + e.Identity
		t.printf("Every authority stops issuing for %s once the revocation reaches it.\n"+
			"Disable the machine's Vault entity, so that the Vault tokens it holds stop working (mount auth/machine assumed):\n"+
			"    vault write identity/lookup/entity alias_name=%s alias_mount_accessor=$(vault read -field=accessor sys/auth/machine)\n"+
			"    vault write identity/entity/id/<id from the lookup> disabled=true\n", e.Identity, alias)
	case cur.Active() && cur.Key != e.Key:
		t.printf("The old key is invalid from now on. ergosumd on %s switches to the new key itself before its next request.\n", e.Identity)
	case cur.Active():
		t.printf("The new checks apply from the next token request of %s.\n", e.Identity)
	default:
		t.printf("Start ergosumd on %s; it obtains a token with its next request.\n", e.Identity)
	}
}

// Show writes the current binding of identity in the file format, ready
// to be edited and bound again.
func (t *Tool) Show(ctx context.Context, identity string, w io.Writer) error {
	b, err := t.Client.Current(ctx, identity)
	if err != nil {
		return err
	}
	if b == nil {
		return fmt.Errorf("%s is not bound", identity)
	}
	by := ""
	if len(b.SignedBy) > 0 {
		by = ", approved by " + strings.Join(b.SignedBy, ", ")
	}
	head := [2]string{
		fmt.Sprintf("# %s: bound at epoch %d%s (%s/%d)", identity, b.Epoch, by, b.Origin, b.Seq),
		`# Edit the key or the checks and run "ergosum bind FILE" to change the binding.`,
	}
	body := RequestText(identity, b.Key, b.Checks)
	if !b.Active() {
		head = [2]string{
			fmt.Sprintf("# %s: revoked at epoch %d%s (%s/%d)", identity, b.Epoch, by, b.Origin, b.Seq),
			`# To bind it again, add the key line from "ergosumd request" and the checks, then run "ergosum bind FILE".`,
		}
		body = RequestText(identity, "", nil)
	}
	lines := append(head[:], body...)
	_, err = io.WriteString(w, strings.Join(lines, "\n")+"\n")
	return err
}

// List writes every binding as a table.
func (t *Tool) List(ctx context.Context, w io.Writer) error {
	l, from, err := t.Client.List(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "IDENTITY\tEPOCH\tSTATE\tKEY\tCHECKS")
	for _, b := range l.Bindings {
		state, key := "bound", b.Key
		if !b.Active() {
			state, key = "revoked", "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", b.Identity, b.Epoch, state, key, checksText(b.Checks))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	noun := "identities"
	if len(l.Bindings) == 1 {
		noun = "identity"
	}
	t.printf("%d %s at %s, trust domain %s.", len(l.Bindings), noun, from, l.TrustDomain)
	for _, kind := range sortedKeys(l.Approvals) {
		ap := l.Approvals[kind]
		t.printf(" %s needs %d of %s.", kind, ap.Threshold, strings.Join(sortedKeys(ap.Admins), ", "))
	}
	t.printf("\n")
	return nil
}

// Revoke writes a revocation file for identity at path (default
// IDENTITY.revoke.txt), shows what it ends and continues as Bind.
func (t *Tool) Revoke(ctx context.Context, identity, path string) error {
	b, err := t.Client.Current(ctx, identity)
	if err != nil {
		return err
	}
	switch {
	case b == nil:
		return fmt.Errorf("%s is not bound", identity)
	case !b.Active():
		return fmt.Errorf("%s is revoked already, at epoch %d", identity, b.Epoch)
	}
	if path == "" {
		path = identity + ".revoke.txt"
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s exists: continue it with \"ergosum bind %s\", or remove it", path, path)
	}
	text := strings.Join([]string{
		fmt.Sprintf("# Revocation of %s, written by ergosum revoke at %s.", identity, t.now()),
		fmt.Sprintf("# It ends the binding of epoch %d (%s).", b.Epoch, describe(b)),
		"kind " + journal.KindBindingRevoked,
		"identity " + identity,
	}, "\n") + "\n"
	if err := keys.WriteFileAtomic(path, []byte(text), 0o644); err != nil { //nolint:gosec // holds no secret
		return err
	}
	t.printf("Revocation of %s written to %s.\n", identity, path)
	return t.Bind(ctx, path)
}

func indent(b []byte) string {
	return "    " + strings.ReplaceAll(strings.TrimRight(string(b), "\n"), "\n", "\n    ") + "\n"
}

func nameList(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return " (" + strings.Join(names, ", ") + ")"
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
