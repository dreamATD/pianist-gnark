package main

import (
	"fmt"
	"log"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/piano"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/pkg/profile"
	"github.com/sunblaze-ucb/simpleMPI/mpi"
)

func main() {
	if mpi.SelfRank == 0 {
		defer profile.Start(profile.MemProfile).Stop()
	}
	runtime.GOMAXPROCS(1)
	dir, _ := os.Getwd()
	fmt.Println("working directory: ", dir)

	mode := os.Args[1]
	if mode == "compile" {
		ccs, err := ReadR1CS("r1cs")
		if err != nil {
			panic(err)
		}
		f, _ := os.Create("compiledCircuit")
		ccs.WriteTo(f)
		f.Close()

		pk, vk, err := piano.Setup(ccs, nil)
		outName := fmt.Sprintf("pk%d", mpi.SelfRank)
		f, _ = os.Create(outName)
		_, err = pk.WriteTo(f)
		if err != nil {
			panic(err)
		}
		f.Close()
		outName = fmt.Sprintf("vk%d", mpi.SelfRank)
		f, _ = os.Create(outName)
		_, err = vk.WriteTo(f)
		if err != nil {
			panic(err)
		}
		f.Close()
		if err != nil {
			panic(err)
		}
	} else {
		// Witnesses instantiation. Witness is known only by the prover,
		// while public w is a public data known by the verifier.
		ccs := plonk.NewCS(ecc.BN254)
		f, _ := os.Open("compiledCircuit")
		ccs.ReadFrom(f)
		f.Close()
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
		pk, _, err := piano.Setup(ccs, witnessPublic)
		{
			f, err := os.Create("memSetup.prof")
			if err != nil {
				log.Fatal("could not create memory profile: ", err)
			}
			defer f.Close() // error handling omitted for example
			runtime.GC()    // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				log.Fatal("could not write memory profile: ", err)
			}
		}

		//_, err := piano.Setup(r1cs, kate, &publicWitness)
		if err != nil {
			log.Fatal(err)
		}

		debug.FreeOSMemory()
		_, err = piano.Prove(ccs, pk, witnessFull)
		if err != nil {
			log.Fatal(err)
		}
	}
}
