#!/bin/bash

# Windows
GOOS=windows go build --trimpath --ldflags="-s -w --buildid=" -o ptForge.exe .

# Linux
go build --trimpath --ldflags="-s -w --buildid=" -o ptForge .
