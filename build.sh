#!/bin/bash

cd Server
cmake CMakeLists.txt
make
cd ..

cd Client
cmake CMakeLists.txt
make
cd ..
