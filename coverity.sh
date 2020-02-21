#!/bin/bash
COV_BUILD=$(which cov-build)
CURL=$(which curl)
COVERITY_SECRET=$(cat ~/.coverity_bpak)

rm -rf cov-int && \
cov-configure --config ../cov.xml \
              --compiler gcc --comptype gcc \
              --template \
              --xml-option=skip_file:".*/src/mbedtls/.*" \
              --xml-option=skip_file:".*/src/uuid/.*" && \
$COV_BUILD --config ../cov.xml --dir cov-int make -j8 && \
tar -czf coverity.tar.gz cov-int && \
$CURL --form token=$COVERITY_SECRET \
        --form email=jonpe960@gmail.com \
        --form file=@coverity.tar.gz \
        --form version="Version" \
        --form description="Description" \
        https://scan.coverity.com/builds\?project\=jonasblixt%2Fbpak && \
rm -rf coverity.tar.gz
