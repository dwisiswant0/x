#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readme="${repo_root}/README.md"

if [[ ! -f "${readme}" ]]; then
  echo "README.md not found at ${readme}" >&2
  exit 1
fi

# Collect module directories (relative to repo root).
mapfile -t module_dirs < <(find "${repo_root}" -name go.mod -type f -print0 | xargs -0 -n1 dirname | sed "s|^${repo_root}/||" | sort)

if [[ ${#module_dirs[@]} -eq 0 ]]; then
  echo "No modules found (go.mod)." >&2
  exit 1
fi

# Extract a one-line description from doc.go for a module directory.
get_desc() {
  local dir="$1"
  local doc="${repo_root}/${dir}/doc.go"

  if [[ ! -f "${doc}" ]]; then
    echo ""
    return 0
  fi

  # Find the first 'Package <name> ...' line and strip the prefix.
  local line
  line=$(grep -m1 '^// Package ' "${doc}" || true)
  if [[ -z "${line}" ]]; then
    echo ""
    return 0
  fi

  # Remove the leading '// Package <name> ' portion.
  local desc
  desc=$(echo "${line}" | sed -E 's#^// Package [^ ]+ ##')
  # Trim leading "provides " (case-insensitive) to keep descriptions concise.
  desc=$(echo "${desc}" | sed -E 's/^[Pp]rovides[ ]+//')
  # Replace bracketed references with inline code (e.g., [os.File] -> `os.File`).
  desc=$(echo "${desc}" | sed -E 's/\[([^][]+)\]/`\1`/g')
  # Ensure trailing period.
  if [[ -n "${desc}" && "${desc}" != *"." ]]; then
    desc="${desc}."
  fi
  echo "${desc}"
}

# Build a docs link from the module path in go.mod.
get_pkg_link() {
  local dir="$1"
  local gomod="${repo_root}/${dir}/go.mod"

  if [[ ! -f "${gomod}" ]]; then
    echo ""
    return 0
  fi

  local mod
  mod=$(awk '/^module[[:space:]]+/ {print $2; exit}' "${gomod}")
  if [[ -z "${mod}" ]]; then
    echo ""
    return 0
  fi

  echo "https://${mod}?godoc=1"
}

# Build catalogs markdown.
exp_children=()
top_level=()

for dir in "${module_dirs[@]}"; do
  if [[ "${dir}" == exp/* && "${dir}" != "exp" ]]; then
    exp_children+=("${dir}")
  else
    top_level+=("${dir}")
  fi
done

IFS=$'\n' read -r -d '' -a top_level_sorted < <(printf '%s\n' "${top_level[@]}" | sort && printf '\0')
IFS=$'\n' read -r -d '' -a exp_children_sorted < <(printf '%s\n' "${exp_children[@]}" | sort && printf '\0')

catalogs_lines=()
for dir in "${top_level_sorted[@]}"; do
  desc=$(get_desc "${dir}")
  pkg_link=$(get_pkg_link "${dir}")
  pkg_suffix=""
  if [[ -n "${pkg_link}" ]]; then
    pkg_suffix=" [docs](${pkg_link})"
  fi
  if [[ -n "${desc}" ]]; then
    catalogs_lines+=("- [${dir}](${dir}): ${desc}${pkg_suffix}")
  else
    catalogs_lines+=("- [${dir}](${dir})${pkg_suffix}")
  fi

  if [[ "${dir}" == "exp" && ${#exp_children_sorted[@]} -gt 0 ]]; then
    for child in "${exp_children_sorted[@]}"; do
      child_desc=$(get_desc "${child}")
      child_pkg_link=$(get_pkg_link "${child}")
      child_pkg_suffix=""
      if [[ -n "${child_pkg_link}" ]]; then
        child_pkg_suffix=" [docs](${child_pkg_link})"
      fi
      if [[ -n "${child_desc}" ]]; then
        catalogs_lines+=("\t- [${child}](${child}): ${child_desc}${child_pkg_suffix}")
      else
        catalogs_lines+=("\t- [${child}](${child})${child_pkg_suffix}")
      fi
    done
  fi
done

catalogs_content=$(printf '%s\n' "${catalogs_lines[@]}")

# Replace the Catalogs section in README.md.
awk -v catalogs="${catalogs_content}" '
  BEGIN { in_catalogs = 0 }
  /^## Catalogs$/ {
    print $0
    print ""
    print catalogs
    in_catalogs = 1
    next
  }
  in_catalogs == 1 {
    if ($0 ~ /^## /) {
      in_catalogs = 0
      print $0
    }
    next
  }
  { print $0 }
' "${readme}" > "${readme}.tmp"

mv "${readme}.tmp" "${readme}"

echo "Updated Catalogs in ${readme}"