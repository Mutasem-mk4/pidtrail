_pidtrail()
{
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    case "${prev}" in
        --pid|--process|--duration|--json|--jsonl|--report-dir)
            return 0
            ;;
    esac

    COMPREPLY=( $(compgen -W "--pid --process --duration --json --jsonl --report-dir --quiet --diagnose --version --" -- "$cur") )
}

complete -F _pidtrail pidtrail

