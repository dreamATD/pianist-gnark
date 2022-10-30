/*
Copyright © 2021 ConsenSys Software Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package test

import (
	"crypto/rand"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/dkzg"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/frontend"

	dkzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/dkzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
)

type srsPair struct {
	dsrs dkzg.SRS
	srs  kzg.SRS
}

const dsrsCachedSize = (1 << 14) + 3

func NewKZGSRSPair(ccs frontend.CompiledConstraintSystem) (dkzg.SRS, kzg.SRS, error) {
	nbConstraints := ccs.GetNbConstraints()
	_, _, public := ccs.GetNbVariables()
	sizeSystem := nbConstraints + public
	kzgSize := ecc.NextPowerOfTwo(uint64(sizeSystem)) + 3

	if kzgSize <= dsrsCachedSize {
		return getCachedDSRS(ccs)
	}

	return newKZGSRSPair(ccs.CurveID(), kzgSize)

}

var dsrsCache map[ecc.ID]srsPair
var dlock sync.Mutex

func init() {
	dsrsCache = make(map[ecc.ID]srsPair)
}
func getCachedDSRS(ccs frontend.CompiledConstraintSystem) (dkzg.SRS, kzg.SRS, error) {
	dlock.Lock()
	defer dlock.Unlock()

	if pair, ok := dsrsCache[ccs.CurveID()]; ok {
		return pair.dsrs, pair.srs, nil
	}

	dsrs, srs, err := newKZGSRSPair(ccs.CurveID(), dsrsCachedSize)
	if err != nil {
		return nil, nil, err
	}
	dsrsCache[ccs.CurveID()] = srsPair{dsrs, srs}
	return dsrs, srs, nil
}

func newKZGSRSPair(curve ecc.ID, kzgSize uint64) (dkzg.SRS, kzg.SRS, error) {
	alpha0, err := rand.Int(rand.Reader, curve.ScalarField())
	if err != nil {
		return nil, nil, err
	}
	alpha1, err := rand.Int(rand.Reader, curve.ScalarField())
	if err != nil {
		return nil, nil, err
	}

	switch curve {
	case ecc.BN254:
		dsrs, err := dkzg_bn254.NewSRS(kzgSize, []*big.Int{alpha0, alpha1})
		if err != nil {
			return nil, nil, err
		}
		srs, err := kzg_bn254.NewSRS(kzgSize, alpha0)
		if err != nil {
			return nil, nil, err
		}
		return dsrs, srs, nil
	default:
		panic("unimplemented")
	}
}
