package main

import (
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/piano"
	"github.com/consensys/gnark/frontend"
	"github.com/sunblaze-ucb/simpleMPI/mpi"
)

func main() {
	runtime.GOMAXPROCS(4)
	dir, _ := os.Getwd()
	fmt.Println("working directory: ", dir)
	ccs, err := ReadR1CS("r1cs")
	if err != nil {
		panic(err)
	}
	a, b, c := ccs.GetNbVariables()
	fmt.Println(a, b, c)

	{
		// Witnesses instantiation. Witness is known only by the prover,
		// while public w is a public data known by the verifier.
		var w R1CSCircuit
		w.Witness = make([]frontend.Variable, 260275)
		for i := 0; i < len(w.Witness); i++ {
			w.Witness[i] = frontend.Variable(0)
		}

		witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
		if err != nil {
			log.Fatal(err)
		}

		witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
		if err != nil {
			log.Fatal(err)
		}

		// public data consists the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.
		pk, vk, err := piano.Setup(ccs, witnessPublic)
		if err != nil {
			log.Fatal(err)
		}

		proof, err := piano.Prove(ccs, pk, witnessFull)
		if err != nil {
			log.Fatal(err)
		}
		if mpi.SelfRank == 0 {
			err = piano.Verify(proof, vk, witnessPublic)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}
