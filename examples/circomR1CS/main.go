package main

import "fmt"

func main() {
	ccs, err := ReadR1CS("./r1cs")
	if err != nil {
		panic(err)
	}
	a, b, c := ccs.GetNbVariables()
	fmt.Println(a, b, c)
}
