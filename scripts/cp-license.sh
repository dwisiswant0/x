#!/bin/bash

set -euo pipefail

# copy the root LICENSE into every directory that contains a go.mod file.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
license_file="${repo_root}/LICENSE"

if [[ ! -f "${license_file}" ]]; then
	echo "LICENSE not found at ${license_file}" >&2
	exit 1
fi

find "${repo_root}" -name go.mod -print0 | while IFS= read -r -d '' modfile; do
	mod_dir="$(dirname "${modfile}")"
	# avoid copying the root LICENSE to itself if the repo root has a go.mod.
	if [[ "${mod_dir}" == "${repo_root}" ]]; then
		continue
	fi

	echo "${mod_dir}" | sed "s|${repo_root}|go.dw1.io/x|"

	cp "${license_file}" "${mod_dir}/LICENSE"
done
