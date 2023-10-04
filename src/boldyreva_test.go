package tss

import (
	"fmt"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/assert"
)

func TestBLS(t *testing.T) {
	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte("DST"))

	n := 1 << 5
	ths := n / 2

	crs := GenBLSCRS(n)
	m := NewBLS(n, ths, crs)

	var signers []int
	var sigmas []bls.G2Jac
	for i := 0; i < ths+1; i++ {
		signers = append(signers, i)
		sigmas = append(sigmas, m.psign(msg, m.pp.signers[i]))
	}

	msig := m.verifyCombine(roMsg, signers, sigmas)
	fmt.Println("Num signers", len(signers), "claimed weight", ths)
	assert.Equal(t, m.gverify(roMsg, msig), true, "BLS Threshold Signature")
}

func TestBLSDleq(t *testing.T) {
	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte("DST"))

	n := 1 << 5
	ths := n / 2

	crs := GenBLSCRS(n)
	m := NewBLS(n, ths, crs)

	var signers []int
	var sigmas []bls.G2Jac
	var pfs []Pf
	for i := 0; i < ths+1; i++ {
		signers = append(signers, i)
		sigma, pf := m.pSignDleq(msg, m.pp.signers[i])
		sigmas = append(sigmas, sigma)
		pfs = append(pfs, pf)
	}

	msig := m.verifyCombineDleq(roMsg, signers, sigmas, pfs)
	fmt.Println("Num signers", len(signers), "claimed weight", ths)
	assert.Equal(t, m.gverify(roMsg, msig), true, "BLS Threshold Signature")
}

func BenchmarkBLS(b *testing.B) {
	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte("DST"))

	n := 64
	ths := n - 1

	crs := GenBLSCRS(n)
	m := NewBLS(n, ths, crs)

	var sigma bls.G2Jac
	b.Run("B1-pSign", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sigma = m.psign(msg, m.pp.signers[0])
		}
	})

	pk0Aff := *new(bls.G1Affine).FromJacobian(&m.pp.signers[0].pKey)
	b.Run("B1-pVerify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			m.pverify(roMsg, sigma, pk0Aff)
		}
	})

	var pf Pf
	b.Run("B2-pSign", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sigma, pf = m.pSignDleq(msg, m.pp.signers[0])
		}
	})

	b.Run("B2-pVerify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			m.pVerifyDleq(roMsg, sigma, pk0Aff, pf)
		}
	})
}

func BenchmarkBLSAgg(b *testing.B) {
	testCases := []struct {
		name string
		n, t int
	}{
		{"64", 64, 64},
		{"256", 256, 256},
		{"1024", 1024, 1024},
	}

	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte{})

	for _, tc := range testCases {
		crs := GenBLSCRS(tc.n)
		m := NewBLS(tc.n, tc.t-1, crs)

		// Picking the first t nodes
		signers := make([]int, tc.t)
		sigmas := make([]bls.G2Jac, tc.t)
		for i := 0; i < tc.t; i++ {
			signers[i] = i
			sigmas[i] = m.psign(msg, m.pp.signers[i])
		}

		var sigma bls.G2Jac
		b.Run(tc.name+"-B1-agg", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sigma = m.verifyCombine(roMsg, signers, sigmas)
			}
		})

		pfs := make([]Pf, tc.t)
		for i := 0; i < tc.t; i++ {
			_, pfs[i] = m.pSignDleq(msg, m.pp.signers[i])
		}
		b.Run(tc.name+"-B2-agg", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sigma = m.verifyCombineDleq(roMsg, signers, sigmas, pfs)
			}
		})

		b.Run(tc.name+"-ver", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.gverify(roMsg, sigma)
			}
		})
	}
}
