package main

import (
	"encoding/json"
	"fmt"
	"log"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/piano"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/sunblaze-ucb/simpleMPI/mpi"
)

var (
	circuitPath string
	r1csPath    string
	pkPath      string
	vkPath      string
)

func parseConfig(jsonFile string) {
	//parse Json file to get the proper circuit path
	//load json
	file, err := os.Open(jsonFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	var f interface{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&f)
	if err != nil {
		log.Fatal(err)
	}
	m := f.(map[string]interface{})
	//get the circuit path
	circuitPath = m["circuitPath."+strconv.Itoa(int(mpi.SelfRank))].(string)
	//get the R1CS path
	r1csPath = m["r1csPath."+strconv.Itoa(int(mpi.SelfRank))].(string)
	//get the pk path
	pkPath = m["pkPath."+strconv.Itoa(int(mpi.SelfRank))].(string)
	//get the vk path
	vkPath = m["vkPath."+strconv.Itoa(int(mpi.SelfRank))].(string)
}

func main() {
	runtime.GOMAXPROCS(8)
	dir, _ := os.Getwd()
	fmt.Println("working directory: ", dir)

	parseConfig("circuitConfig.json")

	mode := os.Args[1]
	if mode == "compile" {
		ccs, err := ReadR1CS(r1csPath)
		if err != nil {
			panic(err)
		}
		f, _ := os.Create(circuitPath)
		ccs.WriteTo(f)
		f.Close()

		pk, vk, err := piano.Setup(ccs, nil)
		if err != nil {
			panic(err)
		}
		f, _ = os.Create(pkPath)
		_, err = pk.WriteTo(f)
		if err != nil {
			panic(err)
		}
		f.Close()
		f, _ = os.Create(vkPath)
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
		f, _ := os.Open(circuitPath)
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
		piano.SetPKVKPath(ccs, pkPath, vkPath)
		pk, _, err := piano.Setup(ccs, witnessPublic)

		//_, err := piano.Setup(r1cs, kate, &publicWitness)
		if err != nil {
			log.Fatal(err)
		}
		_, err = piano.Prove(ccs, pk, witnessFull, witnessPublic)
		if err != nil {
			log.Fatal(err)
		}
	}
}
