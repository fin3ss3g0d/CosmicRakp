#!/bin/bash

rm go.*
go mod init cosmicrakp
go mod tidy
go build
