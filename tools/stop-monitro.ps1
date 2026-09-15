# Stops only the Monitro processes started from THIS folder:
#   python ... <this folder>\src\agentless_monitor_win.py | soc_dashboard.py
#   <this folder>\prometheus-*\prometheus.exe
# Other Python or Prometheus processes on the machine are left untouched.
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path.TrimEnd('\').ToLowerInvariant()
$scripts = @('\src\agentless_monitor_win.py', '\src\soc_dashboard.py') | ForEach-Object { ($root + $_) }

$targets = Get-CimInstance Win32_Process | Where-Object {
    $cmd = if ($_.CommandLine) { $_.CommandLine.ToLowerInvariant() } else { '' }
    $exe = if ($_.ExecutablePath) { $_.ExecutablePath.ToLowerInvariant() } else { '' }
    ($_.Name -like 'python*.exe' -and ($scripts | Where-Object { $cmd.Contains($_) })) -or
    ($_.Name -eq 'prometheus.exe' -and $exe.StartsWith($root + '\prometheus-'))
}

if (-not $targets) {
    Write-Host 'No Monitro processes are running from' $root
    exit 0
}
foreach ($p in $targets) {
    Write-Host ("Stopping PID {0}: {1}" -f $p.ProcessId, $p.Name)
    Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
}
