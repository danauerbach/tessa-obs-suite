#!/bin/bash


# remove existing artifacts
rm -rf ./lambda-packages
rm -f deployment_package.zip

# reinstall needed packages
pip install --target ./lambda-packages crcmod

# need to make sure we install version for the platform of the labmda runtime environment
pip install \
--platform manylinux2014_aarch64 \
--target=lambda-packages \
--implementation cp \
--python-version 3.9 \
--only-binary=:all: --upgrade mseedlib simplemseed

# create new deployment zip
# shellcheck disable=SC2164
cd lambda-packages
rm -rf __pycache__
zip -r ../deployment_package.zip *  > /dev/null
cd ..
zip -r deployment_package.zip lambda_function.py utils

