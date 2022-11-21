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
	"io"
	"math/big"
	"os"

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
)

// ProvingKey stores the data needed to generate a proof:
// * the commitment scheme
// * ql, prepended with as many ones as they are public inputs
// * qr, qm, qo prepended with as many zeroes as there are public inputs.
// * qk, prepended with as many zeroes as public inputs, to be completed by the prover
// with the list of public inputs.
// * sigma_1, sigma_2, sigma_3 in both basis
// * the copy constraint permutation
type ProvingKey struct {
	// Verifying Key is embedded into the proving key (needed by Prove)
	Vk *VerifyingKey

	// qr,ql,qm,qo (in canonical basis).
	Ql, Qr, Qm, Qo []fr.Element

	// LQk (CQk) qk in Lagrange basis (canonical basis), prepended with as many zeroes as public inputs.
	// Storing LQk in Lagrange basis saves a fft...
	CQk, LQk []fr.Element

	// Domains used for the FFTs.
	// Domain[0] = small Domain
	// Domain[1] = big Domain
	Domain [2]fft.Domain
	// Domain[0], Domain[1] fft.Domain

	// Permutation polynomials
	EvaluationPermutationBigDomainBitReversed []fr.Element
	S1Canonical, S2Canonical, S3Canonical     []fr.Element

	// position -> permuted position (position in [0,3*sizeSystem-1])
	Permutation []int64

	ReadPtr io.Reader
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
	KZGSRS dkzg.SRS

	// cosetShift generator of the coset on the small domain
	CosetShift fr.Element

	// S commitments to S1, S2, S3
	S [3]kzg.Digest

	// Commitments to ql, qr, qm, qo prepended with as many zeroes (ones for l) as there are public inputs.
	// In particular Qk is not complete.
	Ql, Qr, Qm, Qo, Qk kzg.Digest
}

// Setup sets proving and verifying keys
func Setup(spr *cs.SparseR1CS, publicWitness bn254witness.Witness) (*ProvingKey, *VerifyingKey, error) {

	// Without Public witness part
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

	nbConstraints := len(spr.Constraints)

	if publicWitness == nil {
		// fft domains
		sizeSystem := uint64(nbConstraints + spr.NbPublicVariables) // spr.NbPublicVariables is for the placeholder constraints
		pk.Domain[0] = *fft.NewDomain(sizeSystem)
		pk.Vk.CosetShift.Set(&pk.Domain[0].FrMultiplicativeGen)

		var t, s *big.Int
		var err error
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
			f, _ := os.Create("GlobalSRS")
			globalSRS.WriteTo(f)
			f.Close()
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
		offset := spr.NbPublicVariables
		for i := 0; i < spr.NbPublicVariables; i++ { // placeholders (-PUB_INPUT_i + qk_i = 0) TODO should return error is size is inconsistant
			pk.Ql[i].SetOne().Neg(&pk.Ql[i])
			pk.Qr[i].SetZero()
			pk.Qm[i].SetZero()
			pk.Qo[i].SetZero()
		}
		for i := 0; i < nbConstraints; i++ { // constraints

			pk.Ql[offset+i].Set(&spr.Coefficients[spr.Constraints[i].L.CoeffID()])
			pk.Qr[offset+i].Set(&spr.Coefficients[spr.Constraints[i].R.CoeffID()])
			pk.Qm[offset+i].Set(&spr.Coefficients[spr.Constraints[i].M[0].CoeffID()]).
				Mul(&pk.Qm[offset+i], &spr.Coefficients[spr.Constraints[i].M[1].CoeffID()])
			pk.Qo[offset+i].Set(&spr.Coefficients[spr.Constraints[i].O.CoeffID()])
		}

		pk.Domain[0].FFTInverse(pk.Ql, fft.DIF)
		pk.Domain[0].FFTInverse(pk.Qr, fft.DIF)
		pk.Domain[0].FFTInverse(pk.Qm, fft.DIF)
		pk.Domain[0].FFTInverse(pk.Qo, fft.DIF)
		fft.BitReverse(pk.Ql)
		fft.BitReverse(pk.Qr)
		fft.BitReverse(pk.Qm)
		fft.BitReverse(pk.Qo)
		// build permutation. Note: at this stage, the permutation takes in account the placeholders
		buildPermutation(spr, &pk)
		// set s1, s2, s3
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
		if vk.S[0], err = dkzg.Commit(pk.S1Canonical, vk.KZGSRS); err != nil {
			return nil, nil, err
		}
		if vk.S[1], err = dkzg.Commit(pk.S2Canonical, vk.KZGSRS); err != nil {
			return nil, nil, err
		}
		if vk.S[2], err = dkzg.Commit(pk.S3Canonical, vk.KZGSRS); err != nil {
			return nil, nil, err
		}
		fmt.Println("pk.Domain[0].Cardinality", pk.Domain[0].Cardinality)
		return &pk, &vk, nil
	} else {
		if mpi.SelfRank == 0 {
			//read globalsrs
			globalSRS = &kzg.SRS{}
			f, _ := os.Open("GlobalSRS")
			globalSRS.ReadFrom(f)
		}
		outName := fmt.Sprintf("pk%d", mpi.SelfRank)
		f, _ := os.Open(outName)
		_, err2 := pk.ReadFrom(f)
		pk.ReadPtr = f
		if err2 != nil {
			panic(err2)
		}
		outName = fmt.Sprintf("vk%d", mpi.SelfRank)
		f, _ = os.Open(outName)
		_, err2 = vk.ReadFrom(f)
		if err2 != nil {
			panic(err2)
		}
		f.Close()

		pk.Vk = &vk
		offset := spr.NbPublicVariables
		pk.CQk = make([]fr.Element, pk.Domain[0].Cardinality)
		pk.LQk = make([]fr.Element, pk.Domain[0].Cardinality)
		for i := 0; i < spr.NbPublicVariables; i++ {
			pk.CQk[i].Set(&publicWitness[i])
			pk.LQk[i].Set(&publicWitness[i])
		}
		for i := 0; i < nbConstraints; i++ {
			pk.CQk[offset+i].Set(&spr.Coefficients[spr.Constraints[i].K])
			pk.LQk[offset+i].Set(&spr.Coefficients[spr.Constraints[i].K])
		}
		pk.Domain[0].FFTInverse(pk.CQk, fft.DIF)
		fft.BitReverse(pk.CQk)

		var err error
		if vk.Qk, err = dkzg.Commit(pk.CQk, vk.KZGSRS); err != nil {
			return nil, nil, err
		}

		return &pk, &vk, nil
	}
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
func buildPermutation(spr *cs.SparseR1CS, pk *ProvingKey) {

	nbVariables := spr.NbInternalVariables + spr.NbPublicVariables + spr.NbSecretVariables
	sizeSolution := int(pk.Domain[0].Cardinality)

	// init permutation
	pk.Permutation = make([]int64, 3*sizeSolution)
	for i := 0; i < len(pk.Permutation); i++ {
		pk.Permutation[i] = -1
	}

	// init LRO position -> variable_ID
	lro := make([]int, 3*sizeSolution) // position -> variable_ID
	for i := 0; i < spr.NbPublicVariables; i++ {
		lro[i] = i // IDs of LRO associated to placeholders (only L needs to be taken care of)
	}

	offset := spr.NbPublicVariables
	for i := 0; i < len(spr.Constraints); i++ { // IDs of LRO associated to constraints
		lro[offset+i] = spr.Constraints[i].L.WireID()
		lro[sizeSolution+offset+i] = spr.Constraints[i].R.WireID()
		lro[2*sizeSolution+offset+i] = spr.Constraints[i].O.WireID()
	}

	// init cycle:
	// map ID -> last position the ID was seen
	cycle := make([]int64, nbVariables)
	for i := 0; i < len(cycle); i++ {
		cycle[i] = -1
	}

	for i := 0; i < len(lro); i++ {
		if cycle[lro[i]] != -1 {
			// if != -1, it means we already encountered this value
			// so we need to set the corresponding permutation index.
			pk.Permutation[i] = cycle[lro[i]]
		}
		cycle[lro[i]] = int64(i)
	}

	// complete the Permutation by filling the first IDs encountered
	for i := 0; i < len(pk.Permutation); i++ {
		if pk.Permutation[i] == -1 {
			pk.Permutation[i] = cycle[lro[i]]
		}
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
	for i := 0; i < nbElmts; i++ {
		pk.S1Canonical[i].Set(&evaluationIDSmallDomain[pk.Permutation[i]])
		pk.S2Canonical[i].Set(&evaluationIDSmallDomain[pk.Permutation[nbElmts+i]])
		pk.S3Canonical[i].Set(&evaluationIDSmallDomain[pk.Permutation[2*nbElmts+i]])
	}

	// Canonical form of S1, S2, S3
	pk.Domain[0].FFTInverse(pk.S1Canonical, fft.DIF)
	pk.Domain[0].FFTInverse(pk.S2Canonical, fft.DIF)
	pk.Domain[0].FFTInverse(pk.S3Canonical, fft.DIF)
	fft.BitReverse(pk.S1Canonical)
	fft.BitReverse(pk.S2Canonical)
	fft.BitReverse(pk.S3Canonical)

	// evaluation of permutation on the big domain
	pk.EvaluationPermutationBigDomainBitReversed = make([]fr.Element, 3*pk.Domain[1].Cardinality)
	copy(pk.EvaluationPermutationBigDomainBitReversed, pk.S1Canonical)
	copy(pk.EvaluationPermutationBigDomainBitReversed[pk.Domain[1].Cardinality:], pk.S2Canonical)
	copy(pk.EvaluationPermutationBigDomainBitReversed[2*pk.Domain[1].Cardinality:], pk.S3Canonical)
	pk.Domain[1].FFT(pk.EvaluationPermutationBigDomainBitReversed[:pk.Domain[1].Cardinality], fft.DIF, true)
	pk.Domain[1].FFT(pk.EvaluationPermutationBigDomainBitReversed[pk.Domain[1].Cardinality:2*pk.Domain[1].Cardinality], fft.DIF, true)
	pk.Domain[1].FFT(pk.EvaluationPermutationBigDomainBitReversed[2*pk.Domain[1].Cardinality:], fft.DIF, true)

}

// getIDSmallDomain returns the Lagrange form of ID on the small domain
func getIDSmallDomain(domain *fft.Domain) []fr.Element {
	fmt.Println("domain.Cardinality", domain.Cardinality)
	res := make([]fr.Element, 3*domain.Cardinality)

	res[0].SetOne()
	res[domain.Cardinality].Set(&domain.FrMultiplicativeGen)
	res[2*domain.Cardinality].Square(&domain.FrMultiplicativeGen)

	for i := uint64(1); i < domain.Cardinality; i++ {
		res[i].Mul(&res[i-1], &domain.Generator)
		res[domain.Cardinality+i].Mul(&res[domain.Cardinality+i-1], &domain.Generator)
		res[2*domain.Cardinality+i].Mul(&res[2*domain.Cardinality+i-1], &domain.Generator)
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
	vk.KZGSRS = *_srs

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
