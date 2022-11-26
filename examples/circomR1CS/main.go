package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	_ "net/http/pprof"
	"os"
	"runtime/debug"
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

func SendString(str string, target int) {
	//string to bytes
	strBytes := []byte(str)
	//send bytes to slave
	length := uint64(len(strBytes))
	lengthBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lengthBytes, length)
	mpi.SendBytes(lengthBytes, uint64(target))
	mpi.SendBytes(strBytes, uint64(target))
}
func RecvString() string {
	lengthBytes, err := mpi.ReceiveBytes(8, 0)
	if err != nil {
		panic(err)
	}
	length := binary.LittleEndian.Uint64(lengthBytes)
	strBytes, err := mpi.ReceiveBytes(length, 0)
	if err != nil {
		panic(err)
	}
	str := string(strBytes)
	return str
}

func parseConfig(jsonFile string) {
	//parse Json file to get the proper circuit path
	//load json
	if mpi.SelfRank == 0 {
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

		for i := 1; i < int(mpi.WorldSize); i++ {
			SendString(m["circuitPath."+strconv.Itoa(i)].(string), i)
			SendString(m["r1csPath."+strconv.Itoa(i)].(string), i)
			SendString(m["pkPath."+strconv.Itoa(i)].(string), i)
			SendString(m["vkPath."+strconv.Itoa(i)].(string), i)
		}
	} else {
		circuitPath = RecvString()
		r1csPath = RecvString()
		pkPath = RecvString()
		vkPath = RecvString()
	}
}

func main() {
	debug.SetGCPercent(-1)
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
