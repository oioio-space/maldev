package transform_test

import (
	"math/rand"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

func TestRandomStubSectionName_ShapeAndDot(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	name := transform.RandomStubSectionName(rng)
	if name[0] != '.' {
		t.Errorf("name[0] = %q, want '.'", name[0])
	}
	for i := 1; i <= 5; i++ {
		if name[i] < 'a' || name[i] > 'z' {
			t.Errorf("name[%d] = %q, want lowercase letter", i, name[i])
		}
	}
	if name[6] != 0 || name[7] != 0 {
		t.Errorf("trailing bytes %02x %02x, want zero NUL pad", name[6], name[7])
	}
}

func TestRandomStubSectionName_DeterministicGivenSeed(t *testing.T) {
	a := transform.RandomStubSectionName(rand.New(rand.NewSource(777)))
	b := transform.RandomStubSectionName(rand.New(rand.NewSource(777)))
	if a != b {
		t.Errorf("same seed produced %q vs %q", a, b)
	}
}

func TestRandomStubSectionName_DiffersAcrossSeeds(t *testing.T) {
	a := transform.RandomStubSectionName(rand.New(rand.NewSource(1)))
	b := transform.RandomStubSectionName(rand.New(rand.NewSource(2)))
	if a == b {
		t.Errorf("seeds 1 and 2 collided on %q — RNG seeded incorrectly?", a)
	}
}
