package main

import (
	"math/rand"
	"testing"
)

func TestSampleAcrossCIDRs(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	// /24 = 254 usable (network+broadcast removed), /32 = 1. total = 255
	cidrs := []string{"192.168.1.0/24", "10.0.0.1/32"}

	// n=0 should return all IPs
	resAll, err := sampleAcrossCIDRs(cidrs, 0, rng)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resAll) != 255 {
		t.Errorf("n=0: expected 255, got %d", len(resAll))
	}

	// n=10 — reservoir sampling
	res10, err := sampleAcrossCIDRs(cidrs, 10, rng)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res10) != 10 {
		t.Errorf("n=10: expected 10, got %d", len(res10))
	}

	// n > total should be capped to total (255)
	resOver, err := sampleAcrossCIDRs(cidrs, 500, rng)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resOver) != 255 {
		t.Errorf("n>total: expected 255, got %d", len(resOver))
	}

	// CIDR larger than /10 should return error
	_, err = sampleAcrossCIDRs([]string{"8.0.0.0/8"}, 5, rng)
	if err == nil {
		t.Error("expected error for CIDR larger than /10")
	}

	// single /32 host
	res32, err := sampleAcrossCIDRs([]string{"1.1.1.1/32"}, 1, rng)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res32) != 1 || res32[0] != "1.1.1.1" {
		t.Errorf("/32: expected [1.1.1.1], got %v", res32)
	}
}
