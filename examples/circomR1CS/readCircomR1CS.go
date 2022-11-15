package main

import (
	"fmt"
	"io/ioutil"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/cs/scs"
)

func readUint32(data []byte, offset int) (uint32, int) {
	return uint32(data[offset]) + uint32(data[offset+1])<<8 + uint32(data[offset+2])<<16 + uint32(data[offset+3])<<24, offset + 4
}
func readUint64(data []byte, offset int) (uint64, int) {
	return uint64(data[offset]) + uint64(data[offset+1])<<8 + uint64(data[offset+2])<<16 + uint64(data[offset+3])<<24 + uint64(data[offset+4])<<32 + uint64(data[offset+5])<<40 + uint64(data[offset+6])<<48 + uint64(data[offset+7])<<56, offset + 8
}

type Section struct {
	offset int
	size   int
}

type R1CSCircuit struct {
	Witness     []frontend.Variable
	Constraints []compiled.R1C
}

func readBigInt(data []byte, size uint32, offset int) (*big.Int, int) {
	buff := data[offset : offset+int(size)]
	//little endian to big endian
	for i := 0; i < len(buff)/2; i++ {
		buff[i], buff[len(buff)-1-i] = buff[len(buff)-1-i], buff[i]
	}
	return new(big.Int).SetBytes(buff), offset + int(size)
}

var (
	n8        uint32
	CoeffArr  []*big.Int
	coefCount uint32
	Labels    []uint64
)

func readLC(data []byte, offset int) (compiled.LinearExpression, int) {
	var lc compiled.LinearExpression
	nTerms, ptr := readUint32(data, offset)
	lc = make([]compiled.Term, nTerms)
	for i := 0; i < int(nTerms); i++ {
		var Index uint32
		var Coeff *big.Int
		Index, ptr = readUint32(data, ptr)
		Coeff, ptr = readBigInt(data, n8, ptr)
		//fmt.Println("Index", Index, "Coeff", Coeff)
		CoeffArr = append(CoeffArr, Coeff)
		lc[i].SetCoeffID(int(coefCount))
		lc[i].SetWireID(int(Index))
		coefCount += 1
	}
	return lc, ptr
}

func readR1C(data []byte, offset int) (compiled.R1C, int) {
	var r compiled.R1C

	r.L, offset = readLC(data, offset)
	r.R, offset = readLC(data, offset)
	r.O, offset = readLC(data, offset)
	return r, offset
}

func SumConstraint(api frontend.API, lc compiled.LinearExpression, wit []frontend.Variable) frontend.Variable {
	var sum frontend.Variable
	var lcTermArray []compiled.Term
	lcTermArray = lc
	neededVariables := make([]frontend.Variable, len(lcTermArray))
	coefs := make([]*big.Int, len(lcTermArray))
	for i := 0; i < len(lcTermArray); i++ {
		term := lc[i]
		coefID := term.CoeffID()
		wireID := term.WireID()
		neededVariables[i] = wit[wireID]
		coefs[i] = CoeffArr[coefID]
		neededVariables[i] = api.Mul(neededVariables[i], coefs[i])
	}
	if len(neededVariables) == 1 {
		return neededVariables[0]
	}
	if len(neededVariables) == 2 {
		return api.Add(neededVariables[0], neededVariables[1])
	}
	if len(neededVariables) == 3 {
		return api.Add(neededVariables[0], api.Add(neededVariables[1], neededVariables[2]))
	}
	if len(neededVariables) == 0 {
		return frontend.Variable(0)
	}
	sum = api.Add(neededVariables[0], neededVariables[1], neededVariables[2:]...)
	return sum
}

func (c *R1CSCircuit) Define(api frontend.API) error {
	for i := 0; i < len(c.Constraints); i++ {
		r := c.Constraints[i]
		a := SumConstraint(api, r.L, c.Witness)
		b := SumConstraint(api, r.R, c.Witness)
		c := SumConstraint(api, r.O, c.Witness)
		api.AssertIsEqual(api.Mul(a, b), c)
	}
	return nil
}

func ReadR1CS(filename string) (frontend.CompiledConstraintSystem, error) {
	//Read the circom R1CS file

	//Map file to byte array
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Load constraints

	// Section 1: unique header section
	ptr := 0
	headerString := string(file[ptr : ptr+4])
	if headerString != "r1cs" {
		return nil, fmt.Errorf("invalid header type")
	}
	version, ptr := readUint32(file, ptr+4)
	//ignore version
	_ = version

	nSections, ptr := readUint32(file, ptr)
	sections := make(map[uint32]Section)
	for i := 0; i < int(nSections); i++ {
		var s Section
		var ht uint32
		var hl uint64
		s.offset = ptr
		ht, ptr = readUint32(file, ptr)
		hl, ptr = readUint64(file, ptr)
		s.offset = ptr
		s.size = int(hl)
		sections[ht] = s
		ptr += int(hl)
		fmt.Println("Section", ht, "size", hl, "offset", s.offset)
	}

	// Header section
	s := sections[1]
	ptr = s.offset
	n8, ptr = readUint32(file, ptr)
	fmt.Println("n8", n8)
	prime, ptr := readBigInt(file, n8, ptr)
	// check bn254
	bn254Prime, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	if prime.Cmp(bn254Prime) != 0 {
		return nil, fmt.Errorf("invalid prime")
	}
	fmt.Println(file[ptr], file[ptr+1], file[ptr+2], file[ptr+3])
	nVars, ptr := readUint32(file, ptr)
	nOutputs, ptr := readUint32(file, ptr)
	nPubIntputs, ptr := readUint32(file, ptr)
	nPriInputs, ptr := readUint32(file, ptr)
	nLabels, ptr := readUint64(file, ptr)
	nConstraints, ptr := readUint32(file, ptr)
	if s.offset+s.size != ptr {
		return nil, fmt.Errorf("invalid header section size")
	}

	// Section 2: load constraints and labels
	circuit := R1CSCircuit{}
	circuit.Constraints = make([]compiled.R1C, nConstraints)
	circuit.Witness = make([]frontend.Variable, nVars)
	fmt.Println("Header info: ", nVars, nOutputs, nPubIntputs, nPriInputs, nLabels, nConstraints)

	s = sections[2]
	ptr = s.offset
	coefCount = 0
	for i := 0; i < int(nConstraints); i++ {
		var singleConstraint compiled.R1C
		singleConstraint, ptr = readR1C(file, ptr)
		circuit.Constraints[i] = singleConstraint
	}
	if s.offset+s.size != ptr {
		return nil, fmt.Errorf("invalid header section size")
	}

	s = sections[3]
	ptr = s.offset
	Labels = make([]uint64, nVars)
	for i := 0; i < int(nVars); i++ {
		Labels[i], ptr = readUint64(file, ptr)
	}
	if s.offset+s.size != ptr {
		return nil, fmt.Errorf("invalid header section size")
	}

	//Section 3: load witness

	//Section 4: build circuit
	ccs, err := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())

	return ccs, err
}
