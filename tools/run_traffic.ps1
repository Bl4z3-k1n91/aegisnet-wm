param(
    [ValidateSet("baseline", "bulk", "business", "voice", "mixed", "stop")]
    [string]$Profile = "mixed",
    [string]$Client = "10.1.10.10",
    [string]$Server = "10.20.10.10",
    [string]$IdentityFile = ""
)

$sshArgs = @("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new")
if ($IdentityFile) {
    $sshArgs += @("-i", $IdentityFile)
}
$target = "root@$Client"

function Invoke-Remote([string]$Command) {
    & ssh @sshArgs $target $Command
    if ($LASTEXITCODE -ne 0) {
        throw "SSH traffic command failed. Install your public key on $Client first."
    }
}

if ($Profile -eq "stop") {
    Invoke-Remote "pkill iperf3 || true"
    exit 0
}

Invoke-Remote "pkill iperf3 || true"

if ($Profile -in @("baseline", "bulk", "mixed")) {
    $rate = if ($Profile -eq "baseline") { "1M" } else { "4M" }
    Invoke-Remote "nohup iperf3 -c $Server -p 5201 -t 3600 -b $rate > /tmp/bulk.log 2>&1 &"
}
if ($Profile -in @("business", "mixed")) {
    Invoke-Remote "nohup iperf3 -c $Server -p 5202 -t 3600 --dscp 26 -b 1M > /tmp/business.log 2>&1 &"
}
if ($Profile -in @("voice", "mixed")) {
    Invoke-Remote "nohup iperf3 -c $Server -p 5203 -u -t 3600 --dscp 46 -b 512K > /tmp/voice.log 2>&1 &"
}

Write-Host "Traffic profile '$Profile' started from $Client to $Server."
