#!/bin/bash

set -euo pipefail

# symlink the root LICENSE into every directory that contains a go.mod file.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
license_file="${repo_root}/LICENSE"

if [[ ! -f "${license_file}" ]]; then
	echo "LICENSE not found at ${license_file}" >&2
	exit 1
fi

find "${repo_root}" -name go.mod -print0 | while IFS= read -r -d '' modfile; do
	mod_dir="$(dirname "${modfile}")"
	# avoid linking the root LICENSE to itself if the repo root has a go.mod.
	if [[ "${mod_dir}" == "${repo_root}" ]]; then
		continue
	fi

	rel_license="$(realpath --relative-to="${mod_dir}" "${license_file}")"
	ln -sfn "${rel_license}" "${mod_dir}/LICENSE"
done
