#compdef pidtrail

_arguments \
  '--pid[trace a specific pid]:pid:' \
  '--process[trace a process name]:name:' \
  '--duration[optional trace duration]:duration:' \
  '--json[write JSON output]:path:_files' \
  '--jsonl[write JSONL output]:path:_files' \
  '--report-dir[write a report bundle]:path:_files -/' \
  '--quiet[disable terminal output]' \
  '--diagnose[run diagnostics and exit]' \
  '--version[print version and exit]'

