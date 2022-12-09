#!/bin/bash
echo "++++++++++++++++++++++++++++++++++++++++"
echo "++ Building Selective Disclouser demo ++"
echo "++++++++++++++++++++++++++++++++++++++++"

echo "+++++ Building org.acreo.veidblock !"
cd org.acreo.veidblock
mvn package && mvn install

cd ..

echo "+++++ Building org.acreo.security !"
cd org.acreo.security
mvn package && mvn install
cd ..

echo "+++++ Building org.ri.se.selectivedisclosure !"
cd org.ri.se.selectivedisclosure
mvn package && mvn install
cd ..
echo "+++++ Building org.ri.se.verifiablecredentials !"
cd org.ri.se.verifiablecredentials
mvn package && mvn install
cd ..
echo "+++++ Building org.ri.se.verifiablecredentials.usecases !"
cd org.ri.se.verifiablecredentials.usecases
mvn package

echo "Successfully built Selective Disclouser demo !"

