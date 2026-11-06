# P5 retirement helper — RUN ONLY AFTER the new agent-vault core is the
# configured MCP in every agent host and has passed acceptance.
#
#   1. Configure the new server in each host:
#        command: <python> -B -m agent_vault.mcp_server
#        env:     AGENT_VAULT_DATA_DIR=<vault dir>, AGENT_VAULT_AGENT_ID=<host id>
#   2. Grant that agent id:  python -B -m agent_vault grant <id> <operation...>
#   3. Verify one synthetic execution per host (scripts/acceptance.py style).
#   4. Run this script to retire the legacy adapters (moved, not deleted).
#   5. After one full week without roll-back need, delete the .retired folder.

param(
    [string]$ToolsDir = "$env:LOCALAPPDATA\hermes\tools"
)

$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$retired = Join-Path $ToolsDir ".retired\$stamp"
New-Item -ItemType Directory -Force -Path $retired | Out-Null

$targets = @("vault_mcp.py", "vault_server_local.py")
$moved = @()
foreach ($name in $targets) {
    $path = Join-Path $ToolsDir $name
    if (Test-Path $path) {
        Move-Item -LiteralPath $path -Destination (Join-Path $retired $name)
        $moved += $name
    }
}

if ($moved.Count -eq 0) {
    Write-Host "Nothing to retire; legacy adapters already absent."
} else {
    Write-Host ("Retired to {0}: {1}" -f $retired, ($moved -join ", "))
    Write-Host "Next: grep agent-host configs for 'vault_mcp' / 'mcp_stdio' and point them at 'python -B -m agent_vault.mcp_server'."
}
