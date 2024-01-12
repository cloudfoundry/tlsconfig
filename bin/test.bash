#!/bin/bash

set -eu
set -o pipefail

go test ./...
