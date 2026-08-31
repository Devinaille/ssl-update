package destination

import (
	"context"
	"errors"
	"testing"
)

type fakeDest struct {
	name string
}

func (f *fakeDest) Name() string                 { return f.name }
func (f *fakeDest) CertName(b CertBundle) string { return "name-" + f.name }
func (f *fakeDest) Deploy(ctx context.Context, cert CertBundle, hint string) (DeployResult, error) {
	return DeployResult{CertID: "fake-id", CertName: "name-" + f.name}, nil
}
func (f *fakeDest) Validate(ctx context.Context) error { return nil }

func fakeFactory(name string, raw map[string]any) (Destination, error) {
	return &fakeDest{name: name}, nil
}

func TestRegister_AndCreate(t *testing.T) {
	Register("test-fake-1", fakeFactory)
	d, err := Create("test-fake-1", "my-dest", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if d.Name() != "my-dest" {
		t.Errorf("Name = %q, want my-dest", d.Name())
	}
}

func TestCreate_UnknownType(t *testing.T) {
	_, err := Create("test-no-such-type-xyz", "x", nil)
	if !errors.Is(err, ErrUnknownType) {
		t.Errorf("err = %v, want ErrUnknownType", err)
	}
}

func TestListTypes_ContainsRegistered(t *testing.T) {
	Register("test-fake-2", fakeFactory)
	types := ListTypes()
	found := false
	for _, ty := range types {
		if ty == "test-fake-2" {
			found = true
		}
	}
	if !found {
		t.Errorf("ListTypes = %v, missing test-fake-2", types)
	}
}
