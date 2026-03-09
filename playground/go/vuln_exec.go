package main

import (
  "os/exec"
)

func run(userInput string) {
  exec.Command("sh", "-c", "echo "+userInput).Run()
}
