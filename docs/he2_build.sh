#!/usr/bin/env bash
rm -rf vita-headers
git clone https://github.com/vitasdk/vita-headers
rm -rf h-encore-2
git clone --recurse-submodules https://github.com/TheOfficialFloW/h-encore-2
cd vita-headers/
git branch -r
git switch TheOfficialFloW-patch-1
vita-libs-gen db_367.yml output
cd output/
make
sudo cp lib*_367_stub* /usr/local/vitasdk/arm-vita-eabi/lib/
cd ..
cd ..
cd h-encore-2/
make