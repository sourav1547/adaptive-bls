package tss

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
)

type BLSParty struct {
	sKey  fr.Element
	pKey  bls.G1Jac
	index int
}

type BLSCRS struct {
	g1      bls.G1Jac
	g1a     bls.G1Affine
	g1Inv   bls.G1Jac
	g1InvAf bls.G1Affine
	g2      bls.G2Jac
	g2a     bls.G2Affine
	domain  *fft.Domain
	H       []fr.Element
}

type BLSParams struct {
	pk      bls.G1Affine
	pKeys   []bls.G1Affine
	signers []BLSParty
}

type BLS struct {
	n   int
	t   int
	crs BLSCRS
	pp  BLSParams
}

func GenBLSCRS(n int) BLSCRS {
	domain := fft.NewDomain(uint64(n))

	H := make([]fr.Element, n)
	omH := domain.Generator
	exp := fr.One()
	for i := 0; i < n; i++ {
		H[i] = exp
		exp.Mul(&exp, &omH)
	}

	gen1, gen2, _, _ := bls.Generators()

	var s1, s2 fr.Element
	s1.SetRandom()
	s2.SetRandom()

	var (
		g1      bls.G1Jac
		g1a     bls.G1Affine
		g1Inv   bls.G1Jac
		g1InvAf bls.G1Affine
		g2      bls.G2Jac
		g2a     bls.G2Affine
	)

	g1.ScalarMultiplication(&gen1, s1.BigInt(&big.Int{}))
	g2.ScalarMultiplication(&gen2, s2.BigInt(&big.Int{}))
	g1a.FromJacobian(&g1)
	g2a.FromJacobian(&g2)
	g1Inv.Neg(&g1)
	g1InvAf.FromJacobian(&g1Inv)

	return BLSCRS{
		g1:      g1,
		g2:      g2,
		g1a:     g1a,
		g2a:     g2a,
		g1Inv:   g1Inv,
		g1InvAf: g1InvAf,
		domain:  domain,
		H:       H,
	}
}

// Here t is the degree of the polynomial
func NewBLS(n, t int, crs BLSCRS) BLS {
	// Assuming n is a power of 2
	bls := BLS{
		n:   n,
		t:   t,
		crs: crs,
	}

	bls.keyGen()
	return bls
}

// (n,t) secret shared keys
func (b *BLS) keyGen() {
	sKeys := make([]fr.Element, b.n)
	pKeys := make([]bls.G1Jac, b.n)

	// Generating t+1 random coefficients
	for i := 0; i < b.t; i++ {
		sKeys[i].SetRandom()
	}

	var pk bls.G1Jac
	var pkAf bls.G1Affine
	pk.ScalarMultiplication(&b.crs.g1, sKeys[0].BigInt(&big.Int{}))
	pkAf.FromJacobian(&pk)

	b.crs.domain.FFT(sKeys, fft.DIF)
	fft.BitReverse(sKeys)

	parties := make([]BLSParty, b.n)
	for i := 0; i < b.n; i++ {
		pKeys[i].ScalarMultiplication(&b.crs.g1, sKeys[i].BigInt(&big.Int{}))
		parties[i] = BLSParty{
			sKey:  sKeys[i],
			pKey:  pKeys[i],
			index: i,
		}
	}
	pKeysAf := bls.BatchJacobianToAffineG1(pKeys)

	b.pp = BLSParams{
		pk:      pkAf,
		pKeys:   pKeysAf,
		signers: parties,
	}
}

// Takes the signing key and signs the message
func (b *BLS) psign(msg Message, signer BLSParty) bls.G2Jac {
	roMsgAf, err := bls.HashToG2(msg, []byte("DST"))
	if err != nil {
		fmt.Printf("Signature error!")
	}

	roMsg := *new(bls.G2Jac).FromAffine(&roMsgAf)

	return *new(bls.G2Jac).ScalarMultiplication(&roMsg, signer.sKey.BigInt(&big.Int{}))
}

// Takes the msg, signature and signing key and verifies the signature
func (b *BLS) pverify(roMsg bls.G2Affine, sigma bls.G2Jac, vk bls.G1Affine) bool {
	var sigmaAff bls.G2Affine
	sigmaAff.FromJacobian(&sigma)

	res, _ := bls.PairingCheck([]bls.G1Affine{vk, b.crs.g1InvAf}, []bls.G2Affine{roMsg, sigmaAff})
	return res
}

func (b *BLS) verifyCombine(msg bls.G2Affine, signers []int, sigmas []bls.G2Jac) bls.G2Jac {
	var vfSigners []int
	var lIdx []int
	for i, idx := range signers {
		if b.pverify(msg, sigmas[i], b.pp.pKeys[idx]) {
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

func (b *BLS) combine(signers []int, sigmas []bls.G2Affine) bls.G2Jac {
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

/**************************
	DLEQ BASED BLS
***************************/

type Pf struct {
	c fr.Element
	z fr.Element
}

func getFSChal(val1 []bls.G1Jac, val2 []bls.G2Jac) fr.Element {
	n1 := len(val1)
	n2 := len(val2)
	hMsg := make([]byte, n1*48+n2*96)

	for i, v := range val1 {
		valAff := *new(bls.G1Affine).FromJacobian(&v)
		mBytes := valAff.Bytes()
		copy(hMsg[i*48:(i+1)*48], mBytes[:])
	}

	shift := n1 * 48
	for i, v := range val2 {
		valAff := *new(bls.G2Affine).FromJacobian(&v)
		mBytes := valAff.Bytes()
		copy(hMsg[shift+i*48:shift+(i+1)*48], mBytes[:])
	}

	hFunc := sha256.New()
	hFunc.Reset()
	return *new(fr.Element).SetBytes(hFunc.Sum(hMsg))
}

// Computing the Chaum-Pedersen Sigma protocol
func (b *BLS) cpProve(pk bls.G1Jac, roMsg bls.G2Jac, sigma bls.G2Jac, sec fr.Element) Pf {
	var r fr.Element
	r.SetRandom()
	rInt := r.BigInt(&big.Int{})
	gr := *new(bls.G1Jac).ScalarMultiplication(&b.crs.g1, rInt)
	hmr := *new(bls.G2Jac).ScalarMultiplication(&roMsg, rInt)

	c := getFSChal([]bls.G1Jac{pk, gr}, []bls.G2Jac{roMsg, hmr})

	var z fr.Element
	z.Mul(&c, &sec)
	z.Add(&z, &r)

	return Pf{c, z}
}

// Checks the correctness of the Chaum-Pedersen Proof
func (b *BLS) cpVerify(pk bls.G1Jac, roMsg bls.G2Jac, sigma bls.G2Jac, pf Pf) bool {
	zInt := pf.z.BigInt(&big.Int{})
	cInt := pf.c.BigInt(&big.Int{})

	pkC := *new(bls.G1Jac).ScalarMultiplication(&pk, cInt)
	sigmaC := *new(bls.G2Jac).ScalarMultiplication(&sigma, cInt)

	gZ := *new(bls.G1Jac).ScalarMultiplication(&b.crs.g1, zInt)
	hZ := *new(bls.G2Jac).ScalarMultiplication(&roMsg, zInt)

	gZ = *gZ.SubAssign(&pkC)
	hZ = *hZ.SubAssign(&sigmaC)

	cLocal := getFSChal([]bls.G1Jac{pk, gZ}, []bls.G2Jac{roMsg, hZ})

	return pf.c.Equal(&cLocal)
}

// Partial signature along
func (b *BLS) pSignDleq(msg Message, signer BLSParty) (bls.G2Jac, Pf) {

	roMsgAf, _ := bls.HashToG2(msg, []byte("DST"))
	roMsg := *new(bls.G2Jac).FromAffine(&roMsgAf)
	sigma := *new(bls.G2Jac).ScalarMultiplication(&roMsg, signer.sKey.BigInt(&big.Int{}))

	pf := b.cpProve(signer.pKey, roMsg, sigma, signer.sKey)
	return sigma, pf
}

func (b *BLS) pVerifyDleq(roMsgAf bls.G2Affine, sigma bls.G2Jac, vkAf bls.G1Affine, pf Pf) bool {
	vk := *new(bls.G1Jac).FromAffine(&vkAf)
	roMsg := *new(bls.G2Jac).FromAffine(&roMsgAf)
	return b.cpVerify(vk, roMsg, sigma, pf)
}

func (b *BLS) verifyCombineDleq(msg bls.G2Affine, signers []int, sigmas []bls.G2Jac, pfs []Pf) bls.G2Jac {
	var vfSigners []int
	var lIdx []int
	for i, idx := range signers {
		if b.pVerifyDleq(msg, sigmas[i], b.pp.pKeys[idx], pfs[i]) {
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

func (b *BLS) gverify(roMsg bls.G2Affine, sigma bls.G2Jac) bool {
	return b.pverify(roMsg, sigma, b.pp.pk)
}
