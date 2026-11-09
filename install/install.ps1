# logos-vpn's installer for Windows, as core serves it
# (GET /api/v1/vpn/install.ps1; docs: contracts/vpn-front, "Installing").
# Core's Connect a machine gives the line that runs it in an elevated
# PowerShell (Windows PowerShell 5.1 or PowerShell 7):
#
#   & ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://core/api/v1/vpn/install.ps1'))) https://core lgv_...
#
# It fetches this core's logos-vpn for the machine with the key, checks it
# against the release's SHA256SUMS, puts it in %ProgramFiles%\Logos (on the
# machine's PATH) and connects with the key. Run again, it replaces the one
# there: core's release, whatever it is.
#
# -CertSha256 is core's certificate's fingerprint: a self-signed core, its
# certificate otherwise refused, checked byte for byte (the line that
# fetches this script pins it the same way). -NoConnect installs and stops
# there. -Dir and -Platform are for tests.
#
# Run as a script block: it never exits (that would close the window); a
# failure throws.
param(
  [Parameter(Mandatory = $true, Position = 0)][string]$Core,
  [Parameter(Mandatory = $true, Position = 1)][string]$Key,
  [string]$CertSha256 = '',
  [switch]$NoConnect,
  [string]$Dir = '',
  [string]$Platform = ''
)
$ErrorActionPreference = 'Stop'
$Core = $Core.TrimEnd('/')
if (-not $Key.StartsWith('lgv_')) { throw "logos-vpn install: $Key is no VPN key (lgv_..., from the tunnel's VPN tab)" }
$onWindows = $env:OS -eq 'Windows_NT'

if (-not $Platform) {
  if (-not $onWindows) { throw 'logos-vpn install: install.ps1 is for Windows; install.sh for Linux and macOS' }
  $cpu = $env:PROCESSOR_ARCHITECTURE
  if ($env:PROCESSOR_ARCHITEW6432) { $cpu = $env:PROCESSOR_ARCHITEW6432 }
  switch ($cpu) {
    'AMD64' { $Platform = 'windows-amd64' }
    'ARM64' { $Platform = 'windows-arm64' }
    default { throw "logos-vpn install: $cpu`: logos-vpn is built for x86-64 and ARM64" }
  }
}
# Installed for the system (no -Dir): an administrator's, on the PATH.
$system = -not $Dir
if ($system) {
  $Dir = Join-Path $env:ProgramFiles 'Logos'
  $me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'logos-vpn install: run it in an elevated PowerShell (Run as administrator)'
  }
}

# TLS 1.2 at least (Windows PowerShell 5.1 may offer older ones alone), and
# core's certificate pinned when its fingerprint is given.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
if ($CertSha256) {
  if (-not ('LogosPin' -as [type])) {
    Add-Type 'public static class LogosPin{public static string Want;public static bool Check(object s,System.Security.Cryptography.X509Certificates.X509Certificate c,System.Security.Cryptography.X509Certificates.X509Chain h,System.Net.Security.SslPolicyErrors e){return System.BitConverter.ToString(System.Security.Cryptography.SHA256.Create().ComputeHash(c.GetRawCertData())).Replace("-","")==Want;}}'
  }
  [LogosPin]::Want = ($CertSha256 -replace '[:\s-]', '').ToUpperInvariant()
  [Net.ServicePointManager]::ServerCertificateValidationCallback = [Delegate]::CreateDelegate([Net.Security.RemoteCertificateValidationCallback], [LogosPin].GetMethod('Check'))
}

$name = "logos-vpn-$Platform"
$file = 'logos-vpn'
if ($Platform.StartsWith('windows-')) { $name += '.exe'; $file += '.exe' }
Write-Host "logos-vpn install: $name from $Core"
function Get-FromCore([string]$path, [string]$to) {
  $wc = New-Object Net.WebClient
  $wc.Headers['Authorization'] = "Bearer $Key"
  try {
    if ($to) { $wc.DownloadFile("$Core$path", $to) } else { return $wc.DownloadString("$Core$path") }
  } catch {
    # Core's why, when it answered: a refused key, a release without the
    # installers.
    $why = $_.Exception.Message
    $we = $_.Exception.InnerException
    if ($we -is [Net.WebException] -and $we.Response) {
      $r = New-Object IO.StreamReader($we.Response.GetResponseStream())
      $why = "$([int]$we.Response.StatusCode) $($r.ReadToEnd())"
      $r.Dispose()
    } elseif ($we) { $why = $we.Message }
    throw "logos-vpn install: $Core$path`: $why"
  } finally { $wc.Dispose() }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('logos-vpn-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $sums = Get-FromCore '/api/v1/vpn/client/SHA256SUMS' ''
  $want = ''
  foreach ($line in ($sums -split "`n")) {
    $f = $line.Trim() -split '\s+'
    if ($f.Count -eq 2 -and ($f[1] -eq $name -or $f[1] -eq "*$name")) { $want = $f[0].ToLowerInvariant() }
  }
  $got = Join-Path $tmp $file
  Get-FromCore "/api/v1/vpn/client/$Platform" $got
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $got).Hash.ToLowerInvariant()
  if (-not $want -or $want -ne $hash) { throw "logos-vpn install: $name does not match its SHA256SUMS ($want): not installed" }
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $exe = Join-Path $Dir $file
  try { Move-Item -Force -LiteralPath $got -Destination $exe }
  catch { throw "logos-vpn install: $exe`: $($_.Exception.Message) (a logos-vpn still running? stop it first)" }
} finally {
  Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue
}

if ($system -and $onWindows) {
  # On the machine's PATH, for the next PowerShell, and this one's.
  $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  if (($path -split ';') -notcontains $Dir) {
    [Environment]::SetEnvironmentVariable('Path', ($path.TrimEnd(';') + ';' + $Dir), 'Machine')
  }
  if (($env:Path -split ';') -notcontains $Dir) { $env:Path = $env:Path.TrimEnd(';') + ';' + $Dir }
  Write-Host "logos-vpn install: $exe, $(& $exe -version)"
} else {
  Write-Host "logos-vpn install: $exe"
}

if ($NoConnect) { return }
$vpnArgs = @()
if ($CertSha256) { $vpnArgs += '-cert-sha256', $CertSha256 }
& $exe @vpnArgs $Core $Key
