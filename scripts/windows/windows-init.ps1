# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

<#
    .DESCRIPTION
    Enables Windows Remote Management on Windows builds.
#>

$ErrorActionPreference = 'Stop'

function Wrap {
    Param([scriptblock]$block)
    Write-Host "+ $($block.ToString().Trim())"
    try {
        Invoke-Command -ScriptBlock $block
    } catch {
        Write-Host "ERROR: $_"
    }
}

Start-Transcript -Path 'C:\winrm.log' -Force

Write-Host 'INIT'

Wrap { Disable-NetFirewallRule -DisplayGroup 'Windows Remote Management' }

# update network to Private
Wrap { New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff' -Force | Out-Null }
Wrap { Set-NetConnectionProfile -InterfaceIndex (Get-NetConnectionProfile).InterfaceIndex -NetworkCategory Private }

Wrap {
    New-NetFirewallRule `
        -Name 'WINRM-HTTPS-In-TCP' `
        -DisplayName 'Windows Remote Management (HTTPS-In)' `
        -Description 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5986]' `
        -Group 'Windows Remote Management' `
        -Program 'System' `
        -Protocol TCP `
        -LocalPort 5986 `
        -Action 'Allow' `
        -Enabled False | Out-Null
}

# add HTTPS listeners
Wrap {
    $cert = New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName 'packer'
    New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Hostname 'packer' -Port 5986 -Force | Out-Null
}

# tune winrm
Wrap { Set-Item -Path WSMan:\localhost\MaxTimeoutms -Value 180000 -Force }
Wrap { Set-Item -Path WSMan:\localhost\Client/TrustedHosts -Value * -Force }

# required for NTLM auth
Wrap { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 2 -Type DWord -Force }
Wrap { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinServerSec' -Value 536870912 -Type DWord -Force }
Wrap { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Force }

# keep service running
Wrap { Set-Service -Name WinRM -StartupType Automatic }
Wrap { Restart-Service -Name WinRM }

Wrap { Enable-NetFirewallRule -DisplayName 'Windows Remote Management (HTTPS-In)' }

# prepare artifacts storage
Wrap { New-Item -Path 'C:\packer' -Type Directory -Force | Out-Null }
Wrap {
    $acl = Get-Acl 'C:\packer'
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule('everyone', 'FullControl', 'ContainerInherit,Objectinherit', 'none', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -Path 'C:\packer' -AclObject $acl
}

Write-Host 'DONE'

Stop-Transcript

Wrap { Move-Item -Path 'C:\winrm.log' -Destination 'C:\packer\' -Force }


# Set network connections provile to Private mode.
Write-Output 'Setting the network connection profiles to Private...'
$connectionProfile = Get-NetConnectionProfile
While ($connectionProfile.Name -eq 'Identifying...') {
    Start-Sleep -Seconds 10
    $connectionProfile = Get-NetConnectionProfile
}
Set-NetConnectionProfile -Name $connectionProfile.Name -NetworkCategory Private

# Set the Windows Remote Management configuration.
Write-Output 'Setting the Windows Remote Management configuration...'
#winrm quickconfig -quiet
#winrm set winrm/config/service '@{AllowUnencrypted="true"}'
#winrm set winrm/config/service/auth '@{Basic="true"}'

# Allow Windows Remote Management in the Windows Firewall.
Write-Output 'Allowing Windows Remote Management in the Windows Firewall...'
netsh advfirewall firewall set rule group="Windows Remote Administration" new enable=yes
netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" new enable=yes action=allow
netsh advfirewall firewall set rule name="Windows Remote Management (HTTPS-In)" new enable=yes action=allow

# DCOM Hardening
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Ole\AppCompat' -Name 'RaiseActivationAuthenticationLevel' -Value '2'  -PropertyType 'dword'

# Reset the autologon count.
# Reference: https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-autologon-logoncount#logoncount-known-issue
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonCount -Value 0
