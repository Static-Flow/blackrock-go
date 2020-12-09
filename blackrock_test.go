package blackrock_go

import (
	"testing"
)

func TestBlackRock(t *testing.T) {
	if !Selftest() {
		t.Error("BlackRock Self Test Failed")
	}
}
