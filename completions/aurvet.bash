# bash completion for aurvet
#
# The subcommand list below is asserted against cmd/aurvet's dispatch switch by
# completions/completions_test.go. A new subcommand that is not added here fails
# that test by name -- completions rot silently otherwise, because a missing
# completion is indistinguishable from "no match".

# AURVET_COMMANDS_BEGIN
_aurvet_commands=(scan baseline review install snapshot explain doctor version)
# AURVET_COMMANDS_END

# AURVET_FLAGS_BEGIN
_aurvet_flags=(
	-json
	-key
	-protected-remote
	-remote
	-signer
	-min-severity
	-no-network
	-offline-root
	-show-recipe
	-since-last
	-tier
)
# AURVET_FLAGS_END

_aurvet() {
	local cur prev i cmd=""
	cur=${COMP_WORDS[COMP_CWORD]}
	prev=${COMP_WORDS[COMP_CWORD - 1]}

	# Flags may appear on either side of the subcommand, so find the
	# subcommand by scanning rather than by position.
	for ((i = 1; i < COMP_CWORD; i++)); do
		local w=${COMP_WORDS[i]}
		case $w in
		-*) continue ;;
		esac
		# Skip the value of a flag that takes one.
		case ${COMP_WORDS[i - 1]} in
		-min-severity | --min-severity | -offline-root | --offline-root) continue ;;
		-tier | --tier | -key | --key | -signer | --signer | -remote | --remote) continue ;;
		esac
		local c
		for c in "${_aurvet_commands[@]}"; do
			if [[ $w == "$c" ]]; then
				cmd=$c
				break
			fi
		done
		[[ -n $cmd ]] && break
	done

	case $prev in
	-min-severity | --min-severity)
		mapfile -t COMPREPLY < <(compgen -W "info suspicious critical" -- "$cur")
		return
		;;
	-tier | --tier)
		# Values only; the tier a run REPORTS is derived from the work it did,
		# so there is nothing here that asserts coverage.
		mapfile -t COMPREPLY < <(compgen -W "meta triage full paranoid" -- "$cur")
		return
		;;
	-offline-root | --offline-root)
		mapfile -t COMPREPLY < <(compgen -d -- "$cur")
		return
		;;
	-key | --key)
		mapfile -t COMPREPLY < <(compgen -f -- "$cur")
		return
		;;
	esac

	if [[ $cur == -* ]]; then
		mapfile -t COMPREPLY < <(compgen -W "${_aurvet_flags[*]}" -- "$cur")
		return
	fi

	case $cmd in
	"")
		mapfile -t COMPREPLY < <(compgen -W "${_aurvet_commands[*]}" -- "$cur")
		;;
	review)
		# A recipe directory or a pkgbase; only the directory is completable.
		mapfile -t COMPREPLY < <(compgen -d -- "$cur")
		;;
	baseline)
		mapfile -t COMPREPLY < <(compgen -W "init append status verify pushed diff" -- "$cur")
		;;
	*)
		# install/snapshot/explain take a pkgbase or a fingerprint. aurvet does
		# not query the AUR from a completion function: a completion must not
		# make a network request the user did not ask for.
		COMPREPLY=()
		;;
	esac
}

complete -F _aurvet aurvet
