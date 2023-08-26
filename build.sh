#!/bin/bash

cd ../compiler
eval ./compile.sh
cd ../compute
make
