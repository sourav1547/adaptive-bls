package tss

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
)

type ABLSParty struct {
	sKey  fr.Element
	rKey  fr.Element
	uKey  fr.Element
	pKey  bls.G1Jac
	index int
}

type ABLSCRS struct {
	g1      bls.G1Jac
	h1      bls.G1Jac
	v1      bls.G1Jac
	g1a     bls.G1Affine
	h1a     bls.G1Affine
	v1a     bls.G1Affine
	g1Inv   bls.G1Jac
	g1InvAf bls.G1Affine
	g2      bls.G2Jac
	g2a     bls.G2Affine
	domain  *fft.Domain
	H       []fr.Element
}

type ABLSParams struct {
	pk      bls.G1Affine
	pKeys   []bls.G1Affine
	signers []ABLSParty
}

type ABLS struct {
	n   int
	t   int
	crs ABLSCRS
	pp  ABLSParams
}

func (b *ABLS) getParamsAff() []bls.G1Affine {
	return []bls.G1Affine{b.crs.g1a, b.crs.h1a, b.crs.v1a}
}

func GenABLSCRS(n int) ABLSCRS {
	domain := fft.NewDomain(uint64(n))

	H := make([]fr.Element, n)
	omH := domain.Generator
	exp := fr.One()
	for i := 0; i < n; i++ {
		H[i] = exp
		exp.Mul(&exp, &omH)
	}

	gen1, gen2, _, _ := bls.Generators()

	var sg, sh, sv, s2 fr.Element
	sg.SetRandom()
	sh.SetRandom()
	sv.SetRandom()
	s2.SetRandom()

	g1 := *new(bls.G1Jac).ScalarMultiplication(&gen1, sg.BigInt(&big.Int{}))
	h1 := *new(bls.G1Jac).ScalarMultiplication(&gen1, sh.BigInt(&big.Int{}))
	v1 := *new(bls.G1Jac).ScalarMultiplication(&gen1, sv.BigInt(&big.Int{}))
	g2 := *new(bls.G2Jac).ScalarMultiplication(&gen2, s2.BigInt(&big.Int{}))
	g1Inv := *new(bls.G1Jac).Neg(&g1)

	return ABLSCRS{
		g1:      g1,
		h1:      h1,
		v1:      v1,
		g2:      g2,
		g1a:     *new(bls.G1Affine).FromJacobian(&g1),
		h1a:     *new(bls.G1Affine).FromJacobian(&h1),
		v1a:     *new(bls.G1Affine).FromJacobian(&v1),
		g2a:     *new(bls.G2Affine).FromJacobian(&g2),
		g1Inv:   g1Inv,
		g1InvAf: *new(bls.G1Affine).FromJacobian(&g1Inv),
		domain:  domain,
		H:       H,
	}
}

// Here t is the degree of the polynomial
func NewABLS(n, t int, crs ABLSCRS) ABLS {
	// Assuming n is a power of 2
	bls := ABLS{
		n:   n,
		t:   t,
		crs: crs,
	}

	bls.keyGen()
	return bls
}

// (n,t) secret shared keys
func (b *ABLS) keyGen() {
	sKeys := make([]fr.Element, b.n)
	rKeys := make([]fr.Element, b.n)
	uKeys := make([]fr.Element, b.n)
	pKeys := make([]bls.G1Jac, b.n)

	// Generating t+1 random coefficients
	for i := 0; i < b.t; i++ {
		sKeys[i].SetRandom()
		rKeys[i].SetRandom()
		uKeys[i].SetRandom()
	}
	rKeys[0].SetZero()
	uKeys[0].SetZero()

	pk := *new(bls.G1Jac).ScalarMultiplication(&b.crs.g1, sKeys[0].BigInt(&big.Int{}))
	pkAf := *new(bls.G1Affine).FromJacobian(&pk)

	b.crs.domain.FFT(sKeys, fft.DIF)
	fft.BitReverse(sKeys)
	b.crs.domain.FFT(rKeys, fft.DIF)
	fft.BitReverse(rKeys)
	b.crs.domain.FFT(uKeys, fft.DIF)
	fft.BitReverse(uKeys)

	parties := make([]ABLSParty, b.n)
	for i := 0; i < b.n; i++ {
		pKeys[i].MultiExp(b.getParamsAff(), []fr.Element{sKeys[i], rKeys[i], uKeys[i]}, ecc.MultiExpConfig{})
		parties[i] = ABLSParty{
			sKey:  sKeys[i],
			rKey:  rKeys[i],
			uKey:  uKeys[i],
			pKey:  pKeys[i],
			index: i,
		}
	}
	pKeysAf := bls.BatchJacobianToAffineG1(pKeys)

	b.pp = ABLSParams{
		pk:      pkAf,
		pKeys:   pKeysAf,
		signers: parties,
	}
}

type SigmaPf struct {
	c  fr.Element
	zs fr.Element
	zr fr.Element
	zu fr.Element
}

// Computing the Chaum-Pedersen Sigma protocol
func (b *ABLS) sigmaProve(ro0Msg bls.G2Affine, ro1Msg bls.G2Affine, sigma bls.G2Jac, signer ABLSParty) SigmaPf {
	var (
		hs, hr, hu fr.Element
		x          bls.G1Jac
		y          bls.G2Jac
	)
	hs.SetRandom()
	hr.SetRandom()
	hu.SetRandom()

	x.MultiExp(b.getParamsAff(), []fr.Element{hs, hr, hu}, ecc.MultiExpConfig{})
	y.MultiExp([]bls.G2Affine{ro0Msg, ro1Msg}, []fr.Element{hs, hr}, ecc.MultiExpConfig{})

	c := getFSChal([]bls.G1Jac{signer.pKey, x}, []bls.G2Jac{sigma, y})

	var zs, zr, zu fr.Element
	zs.Add(zs.Mul(&c, &signer.sKey), &hs)
	zr.Add(zr.Mul(&c, &signer.rKey), &hr)
	zu.Add(zu.Mul(&c, &signer.uKey), &hu)

	return SigmaPf{c, zs, zr, zu}
}

// Checks the correctness of the Chaum-Pedersen Proof
func (b *ABLS) sigmaVerify(ro0Msg bls.G2Affine, ro1Msg bls.G2Affine, pk bls.G1Jac, sigma bls.G2Jac, pf SigmaPf) bool {

	cInt := pf.c.BigInt(&big.Int{})
	pkC := *new(bls.G1Jac).ScalarMultiplication(&pk, cInt)
	sigmaC := *new(bls.G2Jac).ScalarMultiplication(&sigma, cInt)

	var pZ bls.G1Jac
	var hmZ bls.G2Jac
	pZ.MultiExp(b.getParamsAff(), []fr.Element{pf.zs, pf.zr, pf.zu}, ecc.MultiExpConfig{})
	hmZ.MultiExp([]bls.G2Affine{ro0Msg, ro1Msg}, []fr.Element{pf.zs, pf.zr}, ecc.MultiExpConfig{})

	pZ.SubAssign(&pkC)
	hmZ.SubAssign(&sigmaC)

	cLocal := getFSChal([]bls.G1Jac{pk, pZ}, []bls.G2Jac{sigma, hmZ})

	return pf.c.Equal(&cLocal)
}

// Partial signature along
func (b *ABLS) pSign(msg Message, signer ABLSParty) (bls.G2Jac, SigmaPf) {

	dst0 := []byte("DST0")
	dst1 := []byte("DST1")
	ro0Msg, _ := bls.HashToG2(msg, dst0)
	ro1Msg, _ := bls.HashToG2(msg, dst1)
	var sigma bls.G2Jac

	sigma.MultiExp([]bls.G2Affine{ro0Msg, ro1Msg}, []fr.Element{signer.sKey, signer.rKey}, ecc.MultiExpConfig{})
	pf := b.sigmaProve(ro0Msg, ro1Msg, sigma, signer)
	return sigma, pf
}

func (b *ABLS) pVerify(ro0Msg bls.G2Affine, ro1Msg bls.G2Affine, sigma bls.G2Jac, vkAf bls.G1Affine, pf SigmaPf) bool {
	vk := *new(bls.G1Jac).FromAffine(&vkAf)
	return b.sigmaVerify(ro0Msg, ro1Msg, vk, sigma, pf)
}

func (b *ABLS) verifyCombine(ro0Msg bls.G2Affine, ro1msg bls.G2Affine, signers []int, sigmas []bls.G2Jac, pfs []SigmaPf) bls.G2Jac {
	var vfSigners []int
	var lIdx []int

	for i, idx := range signers {
		if b.pVerify(ro0Msg, ro1msg, sigmas[i], b.pp.pKeys[idx], pfs[i]) {
			vfSigners = append(vfSigners, signers[i])
			lIdx = append(lIdx, i)
			if len(lIdx) == b.t+1 {
				break
			}
		}
	}

	vfSigs := make([]bls.G2Affine, len(vfSigners))
	for i, idx := range lIdx {
		vfSigs[i].FromJacobian(&sigmas[idx])
	}

	return b.combine(vfSigners, vfSigs)
}

func (b *ABLS) combine(signers []int, sigmas []bls.G2Affine) bls.G2Jac {
	// If not enough signatures to combine return a empty value
	if len(signers) <= b.t {
		return bls.G2Jac{}
	}

	// Get appropriate lagrange coefficients
	indices := make([]int, b.t+1)
	for i := 0; i <= b.t; i++ {
		indices[i] = signers[i]
	}
	lagH := GetLagAt0(uint64(b.n), indices)

	var thSig bls.G2Jac
	thSig.MultiExp(sigmas, lagH, ecc.MultiExpConfig{})

	return thSig
}

func (b *ABLS) gverify(roMsg bls.G2Affine, sigma bls.G2Jac) bool {
	var sigmaAff bls.G2Affine
	sigmaAff.FromJacobian(&sigma)

	res, _ := bls.PairingCheck([]bls.G1Affine{b.pp.pk, b.crs.g1InvAf}, []bls.G2Affine{roMsg, sigmaAff})
	return res
}
