package tss

import (
	"fmt"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/assert"
)

func TestABLS(t *testing.T) {
	msg := []byte("hello world")

	dst0 := []byte("DST0")
	dst1 := []byte("DST1")

	ro0Msg, _ := bls.HashToG2(msg, dst0)
	ro1Msg, _ := bls.HashToG2(msg, dst1)

	n := 1 << 5
	ths := n / 2
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		weights[i] = i
	}

	crs := GenABLSCRS(n)
	m := NewABLS(n, ths, crs)

	var signers []int
	var sigmas []bls.G2Jac
	var pfs []SigmaPf
	for i := 0; i < ths+1; i++ {
		signers = append(signers, i)
		sigma, pf := m.pSign(msg, m.pp.signers[i])
		sigmas = append(sigmas, sigma)
		pfs = append(pfs, pf)

		pkAff := *new(bls.G1Affine).FromJacobian(&m.pp.signers[i].pKey)
		if m.pVerify(ro0Msg, ro1Msg, sigma, pkAff, pf) {
			fmt.Println(i)
		}
	}

	msig := m.verifyCombine(ro0Msg, ro1Msg, signers, sigmas, pfs)
	assert.Equal(t, m.gverify(ro0Msg, msig), true, "Adaptive BLS Threshold Signature")
}

func BenchmarkABLS(b *testing.B) {
	msg := []byte("hello world")

	dst0 := []byte("DST0")
	dst1 := []byte("DST1")

	ro0Msg, _ := bls.HashToG2(msg, dst0)
	ro1Msg, _ := bls.HashToG2(msg, dst1)

	n := 1 << 5
	ths := n / 2

	crs := GenABLSCRS(n)
	m := NewABLS(n, ths, crs)

	var sigma bls.G2Jac
	var pf SigmaPf
	b.Run("ABLS pSign", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sigma, pf = m.pSign(msg, m.pp.signers[0])
		}
	})

	pk0Aff := *new(bls.G1Affine).FromJacobian(&m.pp.signers[0].pKey)
	b.Run("ABLS pVerify", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			m.pVerify(ro0Msg, ro1Msg, sigma, pk0Aff, pf)
		}
	})
}

func BenchmarkABLSAgg(b *testing.B) {
	testCases := []struct {
		name string
		n, t int
	}{
		{"64", 64, 64},
		{"256", 256, 256},
		{"1024", 1024, 1024},
	}

	msg := []byte("hello world")
	dst0 := []byte("DST0")
	dst1 := []byte("DST1")

	ro0Msg, _ := bls.HashToG2(msg, dst0)
	ro1Msg, _ := bls.HashToG2(msg, dst1)

	for _, tc := range testCases {
		crs := GenABLSCRS(tc.n)
		m := NewABLS(tc.n, tc.t-1, crs)

		signers := make([]int, tc.t)
		sigmas := make([]bls.G2Jac, tc.t)
		pfs := make([]SigmaPf, tc.t)

		for i := 0; i < tc.t; i++ {
			signers[i] = i
			sigma, pf := m.pSign(msg, m.pp.signers[i])
			pfs[i] = pf
			sigmas[i] = sigma
		}

		var sigma bls.G2Jac
		b.Run(tc.name+"-ABLS-agg", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sigma = m.verifyCombine(ro0Msg, ro1Msg, signers, sigmas, pfs)

			}
		})
		assert.Equal(b, m.gverify(ro0Msg, sigma), true, "Adaptive BLS Threshold Signature")
	}
}
