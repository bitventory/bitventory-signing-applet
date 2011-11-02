#!/bin/bash

# Create lib directory
mkdir lib
mkdir lib/org
rm lib/org/slf4j/ -r
rm lib/org/bouncycastle/ -r

# Pull down the logging lib
wget "http://www.slf4j.org/dist/slf4j-1.6.4.tar.gz"
tar xvzf slf4j-1.6.4.tar.gz
cd slf4j-1.6.4/
unzip slf4j-api-1.6.4.jar
mv org/slf4j/ ../lib/org/
cd -

# Pull down bouncy castle
mkdir temp
cd temp
wget "http://www.bouncycastle.org/download/bcprov-jdk16-146.jar"
unzip bcprov-jdk16-146.jar
mv org/bouncycastle ../lib/org/
cd -
rm temp/ -r

