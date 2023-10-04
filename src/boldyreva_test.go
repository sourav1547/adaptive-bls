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

		pkAff := *new(bls.G1Affine).FromJacobian(&m.pp.signers[0].pKey)
		if m.pVerifyDleq(roMsg, sigma, pkAff, pf) {
			fmt.Println(i)
		}
	}

	msig := m.verifyCombineDleq(roMsg, signers, sigmas, pfs)
	fmt.Println("Num signers", len(signers), "claimed weight", ths)
	assert.Equal(t, m.gverify(roMsg, msig), true, "BLS Threshold Signature")
}

func BenchmarkBoldyreva(b *testing.B) {
	msg := []byte("hello world")
	roMsg, _ := bls.HashToG2(msg, []byte("DST"))

	n := 1 << 13
	ths := n / 2

	crs := GenBLSCRS(n)
	m := NewBLS(n, ths, crs)

	var sigma bls.G2Jac
	b.Run("Boldyreva1 pSign", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sigma = m.psign(msg, m.pp.signers[0])
		}
	})

	pk0Aff := *new(bls.G1Affine).FromJacobian(&m.pp.signers[0].pKey)
	b.Run("Boldyreva1 pVerify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			m.pverify(roMsg, sigma, pk0Aff)
		}
	})

	var pf Pf
	b.Run("Boldyreva2 pSign", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sigma, pf = m.pSignDleq(msg, m.pp.signers[0])
		}
	})

	b.Run("Boldyreva2 pVerify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			m.pVerifyDleq(roMsg, sigma, pk0Aff, pf)
		}
	})
}

func BenchmarkAggBoldyreva(b *testing.B) {
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

		// Picking the first t nodes as things are unweighted
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
				// sigmasAff := make([]bls.G2Affine, len(signers))
				// for ii, sigma := range sigmas {
				// 	sigmasAff[ii].FromJacobian(&sigma)
				// }
				sigma = m.verifyCombine(roMsg, signers, sigmas)
			}
		})

		pfs := make([]Pf, tc.t)
		for i := 0; i < b.N; i++ {
			signers[i] = i
			sigma, pf := m.pSignDleq(msg, m.pp.signers[i])
			pfs[i] = pf
			sigmas[i] = sigma
		}
		b.Run(tc.name+"-B2-agg", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// sigmasAff := make([]bls.G2Affine, len(signers))
				// for ii, sigma := range sigmas {
				// 	sigmasAff[ii].FromJacobian(&sigma)
				// }
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
