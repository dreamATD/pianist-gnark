// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gnark DO NOT EDIT

package piano

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/dkzg"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
	"github.com/sunblaze-ucb/simpleMPI/mpi"

	dkzgg "github.com/consensys/gnark-crypto/dkzg"
	bn254witness "github.com/consensys/gnark/internal/backend/bn254/witness"
)

var (
	globalDomain [2]*fft.Domain
	globalSRS    *kzg.SRS
	inputInts    []int
	reader       int
)

// ProvingKey stores the data needed to generate a proof:
// * the commitment scheme
// * ql, prepended with as many ones as they are public inputs
// * qr, qm, qo prepended with as many zeroes as there are public inputs.
// * qk, prepended with as many zeroes as public inputs, to be completed by the prover
// * qd, qnd
// with the list of public inputs.
// * sigma_1, sigma_2, sigma_3, signma_4 in both basis
// * the copy constraint permutation
type ProvingKey struct {
	// Verifying Key is embedded into the proving key (needed by Prove)
	Vk *VerifyingKey

	// qr,ql,qm,qo (in canonical basis).
	Ql, Qr, Qm, Qo []fr.Element

	// qd qnd (in canonical basis).
	Qd, Qnd []fr.Element

	// LQk (CQk) qk in Lagrange basis (canonical basis), prepended with as many zeroes as public inputs.
	// Storing LQk in Lagrange basis saves a fft...
	CQk, LQk []fr.Element

	// Domains used for the FFTs.
	// Domain[0] = small Domain
	// Domain[1] = big Domain
	Domain [2]fft.Domain
	// Domain[0], Domain[1] fft.Domain

	// Permutation polynomials
	EvaluationPermutationBigDomainBitReversed          []fr.Element
	S1Canonical, S2Canonical, S3Canonical, S4Canonical []fr.Element

	// position -> permuted position (position in [0,3*sizeSystem-1])
	Permutation []int64
}

// VerifyingKey stores the data needed to verify a proof:
// * The commitment scheme
// * Commitments of ql prepended with as many ones as there are public inputs
// * Commitments of qr, qm, qo, qk prepended with as many zeroes as there are public inputs
// * Commitments to S1, S2, S3
type VerifyingKey struct {
	// Size circuit
	Size              uint64
	SizeInv           fr.Element
	Generator         fr.Element
	NbPublicVariables uint64

	// Commitment scheme that is used for an instantiation of PLONK
	KZGSRS *dkzg.SRS

	// cosetShift generator of the coset on the small domain
	CosetShift fr.Element

	// S commitments to S1, S2, S3, S4
	S [4]kzg.Digest

	// Commitments to ql, qr, qm, qo prepended with as many zeroes (ones for l) as there are public inputs.
	// In particular Qk is not complete.
	Ql, Qr, Qm, Qo, Qd, Qnd, Qk kzg.Digest
}

// Setup sets proving and verifying keys
func Setup(spr *cs.SparseR1CS, publicWitness bn254witness.Witness) (*ProvingKey, *VerifyingKey, error) {
	var err error
	inputInts, err = readInts("input.txt")
	if err != nil {
		return nil, nil, err
	}
	reader = 0

	globalDomain[0] = fft.NewDomain(mpi.WorldSize)
	if mpi.WorldSize < 6 {
		globalDomain[1] = fft.NewDomain(8 * mpi.WorldSize)
	} else {
		globalDomain[1] = fft.NewDomain(4 * mpi.WorldSize)
	}

	one := fr.One()

	var pk ProvingKey
	var vk VerifyingKey

	// The verifying key shares data with the proving key
	pk.Vk = &vk

	// nbConstraints := len(spr.Constraints)

	// fft domains
	// sizeSystem := uint64(nbConstraints + spr.NbPublicVariables) // spr.NbPublicVariables is for the placeholder constraints
	sizeSystem := uint64(readInt())
	pk.Domain[0] = *fft.NewDomain(sizeSystem)
	pk.Vk.CosetShift.Set(&pk.Domain[0].FrMultiplicativeGen)

	// Transfer randomness t and s to setup dkzg and kzg.
	var t, s *big.Int
	if mpi.SelfRank == 0 {
		for {
			t, err = rand.Int(rand.Reader, spr.CurveID().ScalarField())
			if err != nil {
				return nil, nil, err
			}
			var ele fr.Element
			ele.SetBigInt(t)
			if !ele.Exp(ele, big.NewInt(int64(globalDomain[0].Cardinality))).Equal(&one) {
				break
			}
		}
		for {
			s, err = rand.Int(rand.Reader, spr.CurveID().ScalarField())
			if err != nil {
				return nil, nil, err
			}
			var ele fr.Element
			ele.SetBigInt(s)
			if !ele.Exp(ele, big.NewInt(int64(pk.Domain[0].Cardinality))).Equal(&one) {
				break
			}
		}
		// send t and s to all other processes
		tByteLen := (t.BitLen() + 7) / 8
		sByteLen := (s.BitLen() + 7) / 8
		for i := uint64(1); i < mpi.WorldSize; i++ {
			if err := mpi.SendBytes([]byte{byte(tByteLen)}, i); err != nil {
				return nil, nil, err
			}
			if err := mpi.SendBytes(t.Bytes(), i); err != nil {
				return nil, nil, err
			}
			if err := mpi.SendBytes([]byte{byte(sByteLen)}, i); err != nil {
				return nil, nil, err
			}
			if err := mpi.SendBytes(s.Bytes(), i); err != nil {
				return nil, nil, err
			}
		}
		globalSRS, err = kzg.NewSRS(globalDomain[0].Cardinality, t)
		if err != nil {
			return nil, nil, err
		}
	} else {
		tByteLen, err := mpi.ReceiveBytes(1, 0)
		if err != nil {
			return nil, nil, err
		}
		tbytes, err := mpi.ReceiveBytes(uint64(tByteLen[0]), 0)
		if err != nil {
			return nil, nil, err
		}
		t = new(big.Int).SetBytes(tbytes)
		sByteLen, err := mpi.ReceiveBytes(1, 0)
		if err != nil {
			return nil, nil, err
		}
		sbytes, err := mpi.ReceiveBytes(uint64(sByteLen[0]), 0)
		if err != nil {
			return nil, nil, err
		}
		s = new(big.Int).SetBytes(sbytes)
	}

	// h, the quotient polynomial is of degree 3(n+1)+2, so it's in a 3(n+2) dim vector space,
	// the domain is the next power of 2 superior to 3(n+2). 4*domainNum is enough in all cases
	// except when n<6.
	if sizeSystem < 6 {
		pk.Domain[1] = *fft.NewDomain(8 * sizeSystem)
	} else {
		pk.Domain[1] = *fft.NewDomain(4 * sizeSystem)
	}

	vk.Size = pk.Domain[0].Cardinality
	vk.SizeInv.SetUint64(vk.Size).Inverse(&vk.SizeInv)
	vk.Generator.Set(&pk.Domain[0].Generator)
	vk.NbPublicVariables = uint64(spr.NbPublicVariables)

	dkzgSRS, err := dkzg.NewSRS(vk.Size+3, []*big.Int{t, s}, &globalDomain[0].Generator)
	if err != nil {
		return nil, nil, err
	}
	if err := pk.InitKZG(dkzgSRS); err != nil {
		return nil, nil, err
	}

	// public polynomials corresponding to constraints: [ placholders | constraints | assertions ]
	pk.Ql = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qr = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qm = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qo = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qd = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qnd = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.CQk = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.LQk = make([]fr.Element, pk.Domain[0].Cardinality)

	for i := 0; i < int(sizeSystem); i++ {
		pk.Ql[i].SetInt64(int64(readInt()))
	}
	for i := 0; i < int(sizeSystem); i++ {
		pk.Qr[i].SetInt64(int64(readInt()))
	}
	for i := 0; i < int(sizeSystem); i++ {
		pk.Qm[i].SetInt64(int64(readInt()))
	}
	for i := 0; i < int(sizeSystem); i++ {
		pk.Qo[i].SetInt64(int64(readInt()))
	}
	for i := 0; i < int(sizeSystem); i++ {
		pk.Qd[i].SetInt64(int64(readInt()))
	}
	for i := 0; i < int(sizeSystem); i++ {
		pk.Qnd[i].SetInt64(int64(readInt()))
	}
	for i := 0; i < int(sizeSystem); i++ {
		pk.LQk[i].SetInt64(int64(readInt()))
		pk.CQk[i].Set(&pk.LQk[i])
	}

	pk.Domain[0].FFTInverse(pk.Ql, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qr, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qm, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qo, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qd, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qnd, fft.DIF)
	pk.Domain[0].FFTInverse(pk.CQk, fft.DIF)
	fft.BitReverse(pk.Ql)
	fft.BitReverse(pk.Qr)
	fft.BitReverse(pk.Qm)
	fft.BitReverse(pk.Qo)
	fft.BitReverse(pk.Qd)
	fft.BitReverse(pk.Qnd)
	fft.BitReverse(pk.CQk)

	// build permutation. Note: at this stage, the permutation takes in account the placeholders
	buildPermutation(&pk)

	// set s1, s2, s3, s4
	ccomputePermutationPolynomials(&pk)

	// Commit to the polynomials to set up the verifying key
	if vk.Ql, err = dkzg.Commit(pk.Ql, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qr, err = dkzg.Commit(pk.Qr, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qm, err = dkzg.Commit(pk.Qm, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qo, err = dkzg.Commit(pk.Qo, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qd, err = dkzg.Commit(pk.Qd, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qnd, err = dkzg.Commit(pk.Qnd, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qk, err = dkzg.Commit(pk.CQk, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.S[0], err = dkzg.Commit(pk.S1Canonical, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.S[1], err = dkzg.Commit(pk.S2Canonical, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.S[2], err = dkzg.Commit(pk.S3Canonical, vk.KZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.S[3], err = dkzg.Commit(pk.S4Canonical, vk.KZGSRS); err != nil {
		return nil, nil, err
	}

	return &pk, &vk, nil

}

// buildPermutation builds the Permutation associated with a circuit.
//
// The permutation s is composed of cycles of maximum length such that
//
// 			s. (l∥r∥o) = (l∥r∥o)
//
//, where l∥r∥o is the concatenation of the indices of l, r, o in
// ql.l+qr.r+qm.l.r+qo.O+k = 0.
//
// The permutation is encoded as a slice s of size 3*size(l), where the
// i-th entry of l∥r∥o is sent to the s[i]-th entry, so it acts on a tab
// like this: for i in tab: tab[i] = tab[permutation[i]]
func buildPermutation(pk *ProvingKey) {
	sizeSolution := int(pk.Domain[0].Cardinality)

	// init permutation
	pk.Permutation = make([]int64, 4*sizeSolution)
	for i := range pk.Permutation {
		pk.Permutation[i] = int64(readInt())
	}
}

// ccomputePermutationPolynomials computes the LDE (Lagrange basis) of the permutations
// s1, s2, s3.
//
// 1	z 	..	z**n-1	|	u	uz	..	u*z**n-1	|	u**2	u**2*z	..	u**2*z**n-1  |
//  																					 |
//        																				 | Permutation
// s11  s12 ..   s1n	   s21 s22 	 ..		s2n		     s31 	s32 	..		s3n		 v
// \---------------/       \--------------------/        \------------------------/
// 		s1 (LDE)                s2 (LDE)                          s3 (LDE)
func ccomputePermutationPolynomials(pk *ProvingKey) {

	nbElmts := int(pk.Domain[0].Cardinality)

	// Lagrange form of ID
	evaluationIDSmallDomain := getIDSmallDomain(&pk.Domain[0])

	// Lagrange form of S1, S2, S3
	pk.S1Canonical = make([]fr.Element, nbElmts)
	pk.S2Canonical = make([]fr.Element, nbElmts)
	pk.S3Canonical = make([]fr.Element, nbElmts)
	pk.S4Canonical = make([]fr.Element, nbElmts)
	for i := 0; i < nbElmts; i++ {
		pk.S1Canonical[i].Set(&evaluationIDSmallDomain[pk.Permutation[i]])
		pk.S2Canonical[i].Set(&evaluationIDSmallDomain[pk.Permutation[nbElmts+i]])
		pk.S3Canonical[i].Set(&evaluationIDSmallDomain[pk.Permutation[2*nbElmts+i]])
		pk.S4Canonical[i].Set(&evaluationIDSmallDomain[pk.Permutation[3*nbElmts+i]])
	}

	// Canonical form of S1, S2, S3
	pk.Domain[0].FFTInverse(pk.S1Canonical, fft.DIF)
	pk.Domain[0].FFTInverse(pk.S2Canonical, fft.DIF)
	pk.Domain[0].FFTInverse(pk.S3Canonical, fft.DIF)
	pk.Domain[0].FFTInverse(pk.S4Canonical, fft.DIF)
	fft.BitReverse(pk.S1Canonical)
	fft.BitReverse(pk.S2Canonical)
	fft.BitReverse(pk.S3Canonical)
	fft.BitReverse(pk.S4Canonical)

	// evaluation of permutation on the big domain
	pk.EvaluationPermutationBigDomainBitReversed = make([]fr.Element, 4*pk.Domain[1].Cardinality)
	copy(pk.EvaluationPermutationBigDomainBitReversed, pk.S1Canonical)
	copy(pk.EvaluationPermutationBigDomainBitReversed[pk.Domain[1].Cardinality:], pk.S2Canonical)
	copy(pk.EvaluationPermutationBigDomainBitReversed[2*pk.Domain[1].Cardinality:], pk.S3Canonical)
	copy(pk.EvaluationPermutationBigDomainBitReversed[3*pk.Domain[1].Cardinality:], pk.S4Canonical)
	pk.Domain[1].FFT(pk.EvaluationPermutationBigDomainBitReversed[:pk.Domain[1].Cardinality], fft.DIF, true)
	pk.Domain[1].FFT(pk.EvaluationPermutationBigDomainBitReversed[pk.Domain[1].Cardinality:2*pk.Domain[1].Cardinality], fft.DIF, true)
	pk.Domain[1].FFT(pk.EvaluationPermutationBigDomainBitReversed[2*pk.Domain[1].Cardinality:3*pk.Domain[1].Cardinality], fft.DIF, true)
	pk.Domain[1].FFT(pk.EvaluationPermutationBigDomainBitReversed[3*pk.Domain[1].Cardinality:], fft.DIF, true)

}

// getIDSmallDomain returns the Lagrange form of ID on the small domain
func getIDSmallDomain(domain *fft.Domain) []fr.Element {

	res := make([]fr.Element, 4*domain.Cardinality)

	res[0].SetOne()
	res[domain.Cardinality].Set(&domain.FrMultiplicativeGen)
	res[2*domain.Cardinality].Square(&domain.FrMultiplicativeGen)
	res[3*domain.Cardinality].Mul(&res[domain.Cardinality], &res[2*domain.Cardinality])

	for i := uint64(1); i < domain.Cardinality; i++ {
		res[i].Mul(&res[i-1], &domain.Generator)
		res[domain.Cardinality+i].Mul(&res[domain.Cardinality+i-1], &domain.Generator)
		res[2*domain.Cardinality+i].Mul(&res[2*domain.Cardinality+i-1], &domain.Generator)
		res[3*domain.Cardinality+i].Mul(&res[3*domain.Cardinality+i-1], &domain.Generator)
	}

	return res
}

// InitKZG inits pk.Vk.KZG using pk.Domain[0] cardinality and provided SRS
//
// This should be used after deserializing a ProvingKey
// as pk.Vk.KZG is NOT serialized
func (pk *ProvingKey) InitKZG(srs dkzgg.SRS) error {
	return pk.Vk.InitKZG(srs)
}

// InitKZG inits vk.KZG using provided SRS
//
// This should be used after deserializing a VerifyingKey
// as vk.KZG is NOT serialized
//
// Note that this instantiate a new FFT domain using vk.Size
func (vk *VerifyingKey) InitKZG(srs dkzgg.SRS) error {
	_srs := srs.(*dkzg.SRS)

	if len(_srs.G1) < int(vk.Size) {
		return errors.New("dkzg srs is too small")
	}
	vk.KZGSRS = _srs

	return nil
}

// NbPublicWitness returns the expected public witness size (number of field elements)
func (vk *VerifyingKey) NbPublicWitness() int {
	return int(vk.NbPublicVariables)
}

// VerifyingKey returns pk.Vk
func (pk *ProvingKey) VerifyingKey() interface{} {
	return pk.Vk
}

// readInts reads whitespace-separated ints from r. If there's an error, it
// returns the ints successfully read so far as well as the error value.
func readInts(filename string) (nums []int, err error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "")
	// Assign cap to avoid resize on every append.
	nums = make([]int, 0, len(lines))

	for _, l := range lines {
		// Empty line occurs at the end of the file when we use Split.
		if len(l) == 0 {
			continue
		}
		// Atoi better suits the job when we know exactly what we're dealing
		// with. Scanf is the more general option.
		n, err := strconv.Atoi(l)
		if err != nil {
			return nil, err
		}
		nums = append(nums, n)
	}

	if len(nums) != 15*nums[0] {
		return nil, fmt.Errorf("wrong input array length")
	}
	return nums, nil
}

func readInt() int {
	res := inputInts[reader]
	reader = reader + 1
	return res
}
