package main

import (
  "os/exec"
)

func run() {
  exec.Command("echo", "hello").Run()
}
