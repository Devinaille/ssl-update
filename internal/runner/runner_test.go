package runner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ssl-update/internal/cert"
	"ssl-update/internal/config"
	"ssl-update/internal/destination"
	"ssl-update/internal/state"
)

type fakeDest struct {
	name       string
	deployErr  error
	calls      int
	lastCertID string
}

func (f *fakeDest) Name() string                      { return f.name }
func (f *fakeDest) CertName(c cert.CertBundle) string { return "name-" + f.name }
func (f *fakeDest) Deploy(ctx context.Context, c cert.CertBundle, hint string) (destination.DeployResult, error) {
	f.calls++
	f.lastCertID = hint
	if f.deployErr != nil {
		return destination.DeployResult{CertName: "name-" + f.name}, f.deployErr
	}
	return destination.DeployResult{
		CertID:      "fake-" + f.name,
		CertName:    "name-" + f.name,
		DeployedAt:  time.Now(),
		Fingerprint: "sha256:fake",
	}, nil
}
func (f *fakeDest) Validate(ctx context.Context) error { return nil }

func makeBundle() cert.CertBundle {
	return cert.CertBundle{
		Certificate: []byte("cert"),
		PrivateKey:  []byte("key"),
		MainDomain:  "*.a.com",
		Domains:     []string{"*.a.com"},
	}
}

func newState(t *testing.T) *state.State {
	t.Helper()
	s, err := state.Load(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRun_AllSuccess_ExitZero(t *testing.T) {
	d1 := &fakeDest{name: "a"}
	d2 := &fakeDest{name: "b"}
	items := []NamedDest{
		{Cfg: config.DestinationConfig{Name: "a"}, Dest: d1},
		{Cfg: config.DestinationConfig{Name: "b"}, Dest: d2},
	}
	r := New(items, newState(t), 2)
	code := r.Run(context.Background(), makeBundle())
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if d1.calls != 1 || d2.calls != 1 {
		t.Errorf("calls = %d, %d, want 1 each", d1.calls, d2.calls)
	}
}

func TestRun_RequiredFail_ExitOne(t *testing.T) {
	d1 := &fakeDest{name: "a", deployErr: errors.New("boom")}
	items := []NamedDest{{Cfg: config.DestinationConfig{Name: "a", Required: true}, Dest: d1}}
	r := New(items, newState(t), 1)
	if code := r.Run(context.Background(), makeBundle()); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestRun_OptionalFail_ExitZero(t *testing.T) {
	d1 := &fakeDest{name: "a", deployErr: errors.New("boom")}
	items := []NamedDest{{Cfg: config.DestinationConfig{Name: "a", Required: false}, Dest: d1}}
	r := New(items, newState(t), 1)
	if code := r.Run(context.Background(), makeBundle()); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestRun_AllOptionalFail_StillExitZero(t *testing.T) {
	d1 := &fakeDest{name: "a", deployErr: errors.New("boom")}
	d2 := &fakeDest{name: "b", deployErr: errors.New("boom")}
	items := []NamedDest{
		{Cfg: config.DestinationConfig{Name: "a", Required: false}, Dest: d1},
		{Cfg: config.DestinationConfig{Name: "b", Required: false}, Dest: d2},
	}
	r := New(items, newState(t), 2)
	if code := r.Run(context.Background(), makeBundle()); code != 0 {
		t.Errorf("exit code = %d, want 0 (per spec 9.1)", code)
	}
}

func TestRun_PassesCertIDHint(t *testing.T) {
	st := newState(t)
	st.Set("a:name-a", state.Entry{CertID: "hint-1"})
	d1 := &fakeDest{name: "a"}
	items := []NamedDest{{Cfg: config.DestinationConfig{Name: "a", Required: true}, Dest: d1}}
	r := New(items, st, 1)
	r.Run(context.Background(), makeBundle())
	if d1.lastCertID != "hint-1" {
		t.Errorf("hint = %q, want hint-1", d1.lastCertID)
	}
}

func TestRun_SavesStateOnSuccess(t *testing.T) {
	st := newState(t)
	d1 := &fakeDest{name: "a"}
	items := []NamedDest{{Cfg: config.DestinationConfig{Name: "a", Required: true}, Dest: d1}}
	r := New(items, st, 1)
	r.Run(context.Background(), makeBundle())
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(st.Path())
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var persisted struct {
		Deployments map[string]state.Entry `json:"deployments"`
	}
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("state not valid JSON: %v", err)
	}
	e, ok := persisted.Deployments["a:name-a"]
	if !ok {
		t.Fatalf("deployment not recorded: keys = %v", persisted.Deployments)
	}
	if e.CertID != "fake-a" {
		t.Errorf("CertID = %q, want fake-a", e.CertID)
	}
}

// Regression: --timeout wires ctx.WithTimeout into the runner. When
// ctx is cancelled before Run is called, the runner must not spawn
// any destination goroutines. Previously ctx cancellation was ignored
// entirely.
func TestRun_HonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel
	items := []NamedDest{
		{Cfg: config.DestinationConfig{Name: "a", Required: true}, Dest: &blockingDest{name: "a"}},
		{Cfg: config.DestinationConfig{Name: "b", Required: true}, Dest: &blockingDest{name: "b"}},
		{Cfg: config.DestinationConfig{Name: "c", Required: true}, Dest: &blockingDest{name: "c"}},
	}
	r := New(items, newState(t), 1)
	r.Run(ctx, makeBundle())
	for i, item := range items {
		d := item.Dest.(*blockingDest)
		if d.entered {
			t.Errorf("destination[%d] (%s) entered Deploy despite pre-cancelled ctx", i, d.name)
		}
	}
}

// blockingDest records entry into Deploy and then waits for ctx.
// Used to assert that the runner never calls Deploy when ctx is
// already cancelled.
type blockingDest struct {
	name    string
	entered bool
}

func (b *blockingDest) Name() string                      { return b.name }
func (b *blockingDest) CertName(c cert.CertBundle) string { return "name-" + b.name }
func (b *blockingDest) Deploy(ctx context.Context, c cert.CertBundle, hint string) (destination.DeployResult, error) {
	b.entered = true
	<-ctx.Done()
	return destination.DeployResult{}, ctx.Err()
}
func (b *blockingDest) Validate(ctx context.Context) error { return nil }
