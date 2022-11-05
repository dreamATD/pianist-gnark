package piano

import (
	"io"

	"github.com/consensys/gnark-crypto/dkzg"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/backend/witness"
	cs_bn254 "github.com/consensys/gnark/internal/backend/bn254/cs"

	piano_bn254 "github.com/consensys/gnark/internal/backend/bn254/piano"

	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"

	dkzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/dkzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
)

// Proof represents a piano proof generated by piano.Prove
//
// it's underlying implementation is curve specific (see gnark/internal/backend)
type Proof interface {
	io.WriterTo
	io.ReaderFrom
}

// ProvingKey represents a piano ProvingKey
//
// it's underlying implementation is strongly typed with the curve (see gnark/internal/backend)
type ProvingKey interface {
	io.WriterTo
	io.ReaderFrom
	InitKZG(srs dkzg.SRS) error
	VerifyingKey() interface{}
}

// VerifyingKey represents a piano VerifyingKey
//
// it's underlying implementation is strongly typed with the curve (see gnark/internal/backend)
type VerifyingKey interface {
	io.WriterTo
	io.ReaderFrom
	InitKZG(srs dkzg.SRS) error
	NbPublicWitness() int // number of elements expected in the public witness
}

// Setup prepares the public data associated to a circuit + public inputs.
func Setup(ccs frontend.CompiledConstraintSystem, dkzgSRS dkzg.SRS, kzgSRS kzg.SRS) (ProvingKey, VerifyingKey, error) {

	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		return piano_bn254.Setup(tccs, dkzgSRS.(*dkzg_bn254.SRS), kzgSRS.(*kzg_bn254.SRS))
	default:
		panic("unimplemented")
	}

}

// Prove generates piano proof from a circuit, associated preprocessed public data, and the witness
// if the force flag is set:
// 	will executes all the prover computations, even if the witness is invalid
//  will produce an invalid proof
//	internally, the solution vector to the SparseR1CS will be filled with random values which may impact benchmarking
func Prove(ccs frontend.CompiledConstraintSystem, pk ProvingKey, fullWitness *witness.Witness, opts ...backend.ProverOption) (Proof, error) {

	// apply options
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, err
	}

	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		w, ok := fullWitness.Vector.(*witness_bn254.Witness)
		if !ok {
			return nil, witness.ErrInvalidWitness
		}
		return piano_bn254.Prove(tccs, pk.(*piano_bn254.ProvingKey), *w, opt)

	default:
		panic("unimplemented")
	}
}

// Verify verifies a piano proof, from the proof, preprocessed public data, and public witness.
func Verify(proof Proof, vk VerifyingKey, publicWitness *witness.Witness) error {

	switch _proof := proof.(type) {

	case *piano_bn254.Proof:
		w, ok := publicWitness.Vector.(*witness_bn254.Witness)
		if !ok {
			return witness.ErrInvalidWitness
		}
		return piano_bn254.Verify(_proof, vk.(*piano_bn254.VerifyingKey), *w)

	default:
		panic("unimplemented")
	}
}

// NewCS instantiate a concrete curved-typed SparseR1CS and return a ConstraintSystem interface
// This method exists for (de)serialization purposes
func NewCS(curveID ecc.ID) frontend.CompiledConstraintSystem {
	var r1cs frontend.CompiledConstraintSystem
	switch curveID {
	case ecc.BN254:
		r1cs = &cs_bn254.SparseR1CS{}
	default:
		panic("not implemented")
	}
	return r1cs
}

// NewProvingKey instantiates a curve-typed ProvingKey and returns an interface
// This function exists for serialization purposes
func NewProvingKey(curveID ecc.ID) ProvingKey {
	var pk ProvingKey
	switch curveID {
	case ecc.BN254:
		pk = &piano_bn254.ProvingKey{}
	default:
		panic("not implemented")
	}

	return pk
}

// NewProof instantiates a curve-typed ProvingKey and returns an interface
// This function exists for serialization purposes
func NewProof(curveID ecc.ID) Proof {
	var proof Proof
	switch curveID {
	case ecc.BN254:
		proof = &piano_bn254.Proof{}
	default:
		panic("not implemented")
	}

	return proof
}

// NewVerifyingKey instantiates a curve-typed VerifyingKey and returns an interface
// This function exists for serialization purposes
func NewVerifyingKey(curveID ecc.ID) VerifyingKey {
	var vk VerifyingKey
	switch curveID {
	case ecc.BN254:
		vk = &piano_bn254.VerifyingKey{}
	default:
		panic("not implemented")
	}

	return vk
}