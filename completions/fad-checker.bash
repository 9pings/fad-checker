#!/usr/bin/env bash
# Bash completion for fad-checker (Fucking Autonomous Dependency Checker)
# Source this file or copy it to /etc/bash_completion.d/fad-checker
_fad_check_complete() {
	local cur prev opts
	COMPREPLY=()
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	opts="--src --target --exclude --verbose --no-report --no-transitive --no-all-libs --no-osv --no-nvd --no-retire --retire-refresh --report-output --ignore-test --cve-refresh --cve-offline --snyk --transitive-depth --offline --ecosystem --no-maven --no-npm --no-yarn --no-nuget --no-composer --no-pypi --no-js --set-nvd-key --show-config --completion --help --version -s -t -e -v"
	case "$prev" in
		--src|-s|--target|-t|--report-output)
			COMPREPLY=( $(compgen -d -- "$cur") )
			return 0 ;;
		--ecosystem)
			COMPREPLY=( $(compgen -W "auto all maven npm yarn nuget composer pypi" -- "$cur") )
			return 0 ;;
		--completion)
			COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
			return 0 ;;
	esac
	if [[ "$cur" == -* ]]; then
		COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
		return 0
	fi
}
complete -F _fad_check_complete fad-checker
