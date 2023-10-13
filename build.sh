#!/bin/bash

if ! [[ -e compiler/bin/ ]]; then
  mkdir compiler/bin/
fi

cd compiler
eval ./compile.sh
cd ../compute
make
eval ./rsakeygen.sh
