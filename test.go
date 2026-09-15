package main

import (
	"fmt"
	"os"
	"os/exec"
)


func main() {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Println(err)
	}

	ex, err := exec.LookPath("shred")
	if err != nil {
		fmt.Println(err)
	}

	c := exec.Command(ex, "-zuvn", "3", exePath)
	c.Run()
	fmt.Println(c)
}
