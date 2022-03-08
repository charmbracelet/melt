#!/bin/sh
set -e
rm -rf manpages
mkdir manpages
go run ./cmd/melt man | gzip -c >manpages/melt.1.gz
