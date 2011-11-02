#!/bin/bash

# Compile the applet
mkdir bin
mkdir build
rm bin/* -r
rm build/* -r
javac -cp lib/:plugin.jar -d bin/ src/com/bitventory/core/* src/com/bitventory/applet/* src/com/google/bitcoin/core/* src/com/google/bitcoin/discovery/* src/com/google/bitcoin/store/* src/com/bccapi/core/*

cp -r bin/* build/
cp -r lib/* build/
cp META-INF/ build/ -r

# Create the jar file
cd build/
rm MyBitventoryApplet.jar
zip -r ../MyBitventoryApplet.jar com/ org/ META-INF/
cd -
rm build/ -r
