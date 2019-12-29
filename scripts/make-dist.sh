#!/bin/bash
#
#  Generate the ArgX distribution files
#

# First, check if this is a tagged release
semver_re="(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-((0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(\+([0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*))?"
release_ver=$(git tag --points-at HEAD | egrep -o "^release-$semver_re$")
git_sha=$(git rev-parse HEAD)

# Work out what to use as the version suffix
if [[ -n "$release_ver" ]]; then
    version_suffix=$(echo "$release_ver" | cut -c 9-)
else
    version_suffix=$(echo "$git_sha" | cut -c -8)
fi

if ! git diff-index --quiet HEAD --; then
    version_suffix=$(echo "$git_sha" | cut -c -8)-unclean
fi

# Make the dist folder if it doesn't already exist
if [[ ! -d dist ]]; then
    mkdir dist
fi

# Construct the filename
distfile=dist/ArgX-$version_suffix.zip

# Build the release zip file
rm -f $distfile
7z a -tzip $distfile $(cat MANIFEST) -xr!*~
