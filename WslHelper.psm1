function Invoke-Wsl {
    <#
        .SYNOPSIS
            wsl.exe ignores Console.Encoding and always outputs UTF-16
            Set Console.Encoding to UTF-16 so the console can handle it
    #>
    [Console]::OutputEncoding, $Encoding = [Text.Encoding]::Unicode, [Console]::OutputEncoding
    wsl.exe @args
    [Console]::OutputEncoding = $Encoding
}

Set-Alias wsle Invoke-Wsl -Scope Global

function ConvertFrom-IniContent {
    <#
        .SYNOPSIS
            Parses content from ini/conf files into nested hashtables.
        .EXAMPLE
            Get-Content \\wsl.localhost\Ubuntu\etc\wsl.conf | ConvertFrom-IniContent
        .EXAMPLE
            ConvertFrom-IniContent (Get-Content ~\.wslconf -Raw)
        .EXAMPLE
            "
            [automount]
            enabled = true
            mountFsTab = true

            [network]
            generateResolvConf = false
            " | ConvertFrom-IniContent

            Name                           Value
            ----                           -----
            automount                      {enabled, mountFsTab}
            network                        {generateResolvConf}

    #>
    [CmdletBinding()]
    param(
        # The content of an ini file
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$InputObject
    )
    begin {
        $StringBuilder = [System.Collections.Generic.List[string]]::new()
    }
    process {
        $StringBuilder.AddRange([string[]]@($InputObject -split "[\r\n]+"))
    }
    end {
        $ini = [ordered]@{}
        switch -regex ($StringBuilder) {
            "^\s*\[(.*)\]\s*$" {
                $section = $ini
                foreach ($level in $matches[1] -split "\.") {
                    if (!$section[$level]) {
                        $section[$level] = [ordered]@{}
                    }
                    $section = $section[$level]
                }
            }
            "^\s*(.+?)\s*=\s*(.+?)\s*$" {
                $name, $value = $matches[1..2]
                $section[$name] = $value
            }
        }
        $ini
    }
}

function ConvertTo-IniContent {
    <#
        .SYNOPSIS
            Convert nested hashtables to ini syntax.
            Supports recursively nested hashtables by putting dots in the section names.
        .EXAMPLE
            Get-Content \\wsl.localhost\Ubuntu\etc\wsl.conf | ConvertFrom-IniContent
        .EXAMPLE
            ConvertFrom-IniContent (Get-Content ~\.wslconf -Raw)
        .EXAMPLE
            @{
                automount = @{
                    enabled = $true
                    mountFsTab = $true
                }
                network = @{
                    generateResolvConf = $false
                }
            } | ConvertTo-IniContent

            [automount]
            enabled = True
            mountFsTab = True
            [network]
            generateResolvConf = False
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [System.Collections.IDictionary]$InputObject,

        [Parameter()]
        [string[]]$Section
    )
    process {
        if ($Section) { "[$($Section -join ".")]" }
        $after = @()
        foreach ($kv in $InputObject.GetEnumerator()) {
            if ($kv.value -is [System.Collections.IDictionary]) {
                $after += $kv
            } else {
                $kv.key + " = " + $kv.value
            }
        }
        foreach ($kv in $after) {
            $Nested = $section + $kv.Key
            $kv.value | ConvertTo-IniContent -Section $Nested
        }
    }
}




function Add-WslUser {
    <#
        .SYNOPSIS
            Adds a user to a WSL distro
        .DESCRIPTION
            Adds a user to a WSL distro.

            If you pass in a credential with no password, it leaves the user passwordless (which breaks sudo).
            You must later run passwd to set it:

            wsl -d $Distribution -u root passwd $($Env:USERNAME.ToLower())
    #>
    [CmdletBinding()]
    param(
        # The distro to add the user to
        [Parameter(Mandatory)]
        $Distribution,

        # The user and password to add
        [Parameter(Mandatory)]
        [PSCredential]$Credential
    )
    if ($Credential.Password.Length -eq 0) {
        Write-Warning "Creating passwordless user"
        # If we are interactive, you can leave off the --disabled-password and it would prompt, but this is for automation...
        Write-Host "`n>" wsl "-d" $Distribution "-u" root adduser "--gecos" GECOS "--disabled-password" $Credential.UserName.ToLower()
        wsl -d $Distribution -u root adduser --gecos GECOS --disabled-password $Credential.UserName.ToLower()
    } else {
        Write-Host "`n>" wsl "-d" $Distribution "-u" root adduser "--gecos" GECOS $Credential.UserName.ToLower()
        # You need to send the password twice to answer the prompt:
        "{0}`n{0}`n" -f $Credential.GetNetworkCredential().Password |
            wsl -d $Distribution -u root adduser --gecos GECOS $Credential.UserName.ToLower()
    }
    Write-Host "`n>" wsl "-d" $Distribution "-u" root usermod "-aG" sudo $Credential.UserName.ToLower()
    wsl -d $Distribution -u root usermod -aG sudo $Credential.UserName.ToLower()
}

function Install-WslDistro {
    <#
        .SYNOPSIS
            Installs a WSL Distribution non-interactively
        .DESCRIPTION
            Installs a WSL Distribution non-interactively, adds a user and sets it as default.
    #>
    [CmdletBinding(DefaultParameterSetName = "Secured")]
    param(
        # The distribution to install
        [Parameter(Position = 0)]
        $Distribution = "ubuntu",

        # The default user for this distribution (by default, your user name, but all in lowercase)
        [Parameter(ParameterSetName = "Insecure")]
        $Username = $Env:USERNAME.ToLower(),

        # Credential for the user, so you can set the password. Your user name must be all lowercase.
        [Parameter(Mandatory, ParameterSetName = "NonInteractive")]
        [PSCredential]$Credential,

        # Makes this the default WSL distro
        [switch]$Default,

        # Force the install to happen non-interactively:
        # - Without opening ubuntu
        # - Without prompting for a user/password
        [Parameter(Mandatory, ParameterSetName = "NonInteractive")]
        [switch]$NonInteractive
    )
    if ($NonInteractive) {
        # Install the distribution non-interactively by running `wsl --install` AND THEN `DistroName install`
        Write-Host "`n>" wsl --install $Distribution --no-launch
        wsl --install $Distribution --no-launch

        Write-Host ">" $Distribution install --root
        &$Distribution install --root


        # Then create the user after the fact
        if (!$Credential) {
            $Credential = [PSCredential]::new($Username.ToLower(), [securestring]::new())
        }
        Add-WslUser $Distribution $Credential

        # Sets the default user
        if (Get-Command $Distribution) {
            Write-Host $Distribution config --default-user $Credential.UserName.ToLower()
            & $Distribution config --default-user $Credential.UserName.ToLower()
        }

        if ($Credential.Password.Length -eq 0) {
            Write-Warning "$Distribution distro is installed. You may need to set a password with: wsl -d $Distribution -u root passwd $($Env:USERNAME.ToLower())"
        }
    } else {
        # Install the distribution interactively, by running `wsl --install` and letting it prompt for the username and password
        Write-Host "`n>" wsl --install $Distribution
        wsl --install $Distribution
    }

    if ($Default) {
        # Set the default distro to $Distribution
        Write-Host "`n>" wsl --set-default $Distribution
        wsl --set-default $Distribution
    }
}

function Set-WslContent {
    # .SYNOPSIS
    #    A wrapper for piping content into WSL files, even if they aren't writeable as the default user.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        # The name of the linux distro
        [Parameter()]
        [string]$Distribution,

        # The linux file path (should be an absolute path)
        [Parameter(Mandatory)]
        [string]$Path,

        # If set, run as root to write to protected paths.
        # Remember: This means the owner will be root!
        [switch]$Sudo,

        # The content to write to the file
        [Parameter(Mandatory)]
        [Alias("Content")]
        [string[]]$InputObject
    )
    begin {
        $Content = @()
    }
    process {
        $Content += $InputObject
    }
    end {
        $params = @()
        if ($Sudo) {
            $params += "-u", "root"
        }
        if ($Distribution) {
            $params += "-d", $Distribution
        }
        Write-Information "@`"`n$($InputObject -join "`n")`n`"@ | wsl $($params -join ' ') sh -c `"cat - > '$Path'`""
        $InputObject -join "`n" | wsl @params sh -c "cat - > '$Path'"
    }
}

function Add-WslContent {
    # .SYNOPSIS
    #    A wrapper for piping content into WSL files, even if they aren't writeable as the default user.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        # The name of the linux distro
        [Parameter()]
        [string]$Distribution,

        # The linux file path (should be an absolute path)
        [Parameter(Mandatory)]
        [string]$Path,

        # If set, run as root to write to protected paths.
        # Remember: This means the owner will be root!
        [switch]$Sudo,

        # The content to write to the file
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("Content")]
        [string[]]$InputObject
    )
    begin {
        $Content = @()
    }
    process {
        $Content += $InputObject
    }
    end {
        $params = @()
        if ($Sudo) {
            $params += "-u", "root"
        }
        if ($Distribution) {
            $params += "-d", $Distribution
        }
        Write-Information "@`"`n$($InputObject -join "`n")`n`"@ | wsl $($params -join ' ') sh -c `"cat - >> '$Path'`""
        $Content -join "`n" | wsl @params sh -c "cat - >> '$Path'"
    }
}

function Update-WslCertificates {
    <#
        .SYNOPSIS
            Copy certificates from LocalMachine\Root to a WSL distro.
            Thanks ZScaler Internet Security. 😑
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSPossibleIncorrectUsageOfRedirectionOperator', '')]
    param(
        # Certificate thumbprints to copy into WSL distros for trust.
        # Default: certs in Cert:\LocalMachine\Root that match "LD Enterprise", "LoanDepot", or "ZScaler"
        # NOTE: this means that if you DO NOT have any of those certificates on your machine already, this does nothing, by default.
        [Parameter(ValueFromPipeline)]
        [array]$Certificates = $((Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -Match "LD Enterprise|LoanDepot|ZScaler").Thumbprint),

        # The Distribution to configure (by default, all of them)
        # Be careful when calculating the values for this: WSL output is UTF-16 encoded.
        # You must use `Invoke-Wsl` to be successful writing code against the output of WSL
        [string[]]$Distribution = $(Invoke-Wsl --list --quiet | Where-Object { $_ -notmatch "^docker|-data$"} )
    )
    begin {
        $AllCertificates = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    }
    process {
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$MoreCertificates =
        @($Certificates).Where{ $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] }
        $null = $AllCertificates.AddRange($MoreCertificates)
        if (($CertificateNames = @($Certificates).Where{ $_ -is [string] })) {
            Push-Location Cert:\LocalMachine\Root
            $MoreCertificates = @(Get-Item $CertificateNames -ErrorAction Ignore).Where{ $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] }
            $null = $AllCertificates.AddRange($MoreCertificates)
            Pop-Location
        }
    }
    end {
        foreach ($distro in $Distribution) {
            # Ignore errors. Some like "docker-desktop-data" cannot execvpe() and will throw, so we'll ignore them
            if (!(Invoke-Wsl --distribution $distro which update-ca-certificates 2>$null)) {
                Write-Warning "$distro missing update-ca-certificates -- not updating CA certificates"
                continue
            }
            $AllCertificates | ForEach-Object {
                if (!($Name = $_.Subject -replace ".*CN=([^,]*).*", '$1' -replace " ", "_")) {
                    $Name = $_.Thumbprint
                }
                Write-Verbose "Adding Certificate $($_.Thumbprint) for $($Name)"
                $rawcert = @(
                    "-----BEGIN CERTIFICATE-----"
                    [Convert]::ToBase64String($_.RawData)
                    "-----END CERTIFICATE-----"
                )
                Set-WslContent -Distribution $distro -Sudo -Path "/usr/local/share/ca-certificates/$Name.crt" -Content $rawcert
            }

            Write-Verbose "update-ca-certificates on $($Name)"
            Invoke-Wsl -u root --distribution $distro update-ca-certificates
        }
    }
}

function Update-WslDns {
    <#
        .SYNOPSIS
            Update the DNS servers on WSL distros to fix connectivity when VPNs mess with it.
            https://learn.microsoft.com/en-us/windows/wsl/troubleshooting#wsl-has-no-network-connectivity-once-connected-to-a-vpn

        .DESCRIPTION
            You should run Disable-WslGenerateResolvConf if this works to restore your connectivity.

            Since this reaches into each distro and runs commands with `sudo` one at a time,
            You MIGHT want to use `sudo visudo` on each distro to remove the password request from sudo to make this go smoothly.
            %sudo   ALL=(ALL:ALL) NOPASSWD: ALL

            You can put it back at the end by removing "NOPASSWD:" from again.

            Recommended you run with -Verbose the first time
    #>
    [Alias("Update-WslResolv")]
    [CmdletBinding()]
    param(
        # DNS Servers you want to use in WSL (by default copied from your local DNS client settings)
        [ValidateNotNullOrEmpty()]
        [string[]]$DnsServers = $(Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -Expand ServerAddresses -Unique),

        # DNS Suffixes you want to search in WSL (by default copied from your local DNS client settings)
        [ValidateNotNullOrEmpty()]
        [string[]]$DnsSuffixes = $((Get-DnsClientGlobalSetting).SuffixSearchList),

        # The Distribution to configure (by default, all of them)
        # Be careful when calculating the values for this:
        # There is current a bug in wsl that causes it to output nulls after every character
        [ValidateNotNullOrEmpty()]
        [string[]]$Distribution = $(Invoke-Wsl --list --quiet | Where-Object { $_ -notmatch "^docker|-data$" })
    )
    foreach ($distro in $Distribution) {
        Write-Verbose "Update /etc/resolv.conf for $distro"
        wsl -u root --distribution $distro sh -c "cp /etc/resolv.conf /etc/resolv.conf.new && unlink /etc/resolv.conf && mv /etc/resolv.conf.new /etc/resolv.conf"
        Set-WslContent -Distribution $Distro -Sudo -Path /etc/resolv.conf @(
            # Use systemd:
            "nameserver 127.0.0.53"
            $DnsServers | ForEach-Object { "nameserver $_" }
            "nameserver 1.1.1.1" # Cloudflare
            # "nameserver 8.8.8.8" # Google
            # "nameserver 9.9.9.9" # Quad9
            if ($DnsSuffixes) { "search $($DnsSuffixes -join ' ')" }
        )

        # Get the current configuration
        if (($resolved = wsl --distribution $distro sh -c "cat /etc/systemd/resolved.conf" | ConvertFrom-IniContent)) {
            Write-Verbose "Update /etc/systemd/resolved.conf for $distro"
            $resolved.Resolve.DNS = $DnsServers + "8.8.8.8" -join " "
            $resolved.Resolve.Domains = $DnsSuffixes -join ' '

            Set-WslContent -Distribution $Distro -Sudo -Path /etc/systemd/resolved.conf @($resolved | ConvertTo-IniContent)
        }

        Set-WslGenerateResolvConf -Distribution $distro -generateResolvConf:$false
    }
}

function Set-WslGenerateResolvConf {
    <#
        .SYNOPSIS
            Update wsl.conf to disable generateResolvConf
            https://learn.microsoft.com/en-us/windows/wsl/troubleshooting#wsl-has-no-network-connectivity-once-connected-to-a-vpn

        .DESCRIPTION
            You should rarely need do this, but we've had a lot of trouble with AnyConnect.

            If you DO this, to restore generating the resolv.conf you will need to Enable-WslGenerateResolvConf

    #>
    [CmdletBinding()]
    param(
        # The Distribution to configure (by default, all of them)
        # Be careful when calculating the values for this:
        # There is current a bug in wsl that causes it to output nulls after every character
        [ValidateNotNullOrEmpty()]
        [string[]]$Distribution = $(Invoke-Wsl --list --quiet | Where-Object { $_ -notmatch "^docker|-data$" }),

        # If set, enables (re)generation of the resolv.conf file
        [switch]$generateResolvConf,

        # Force a restart of the distro(s). Required for generateResolvConf to take effect
        [switch]$Restart
    )
    foreach ($distro in $Distribution) {
        Write-Verbose "Update /etc/wsl.conf for $distro"
        #$wslConfPath = "\\wsl.localhost\$distro\etc\wsl.conf"
        $wslConfPath = "/etc/wsl.conf"

        # Get the current content, if there is any
        if (($wsl = wsl --distribution $distro sh -c "cat $wslConfPath" | ConvertFrom-IniContent)) {
            if (!($wsl["network"])) {
                $wsl["network"] = [ordered]@{}
            }
            $wsl["network"]["generateResolvConf"] = if ($generateResolvConf) { "true" } else { "false" }
        } else {
            $wsl = [ordered]@{
                network = [ordered]@{
                    "generateResolvConf" = if ($generateResolvConf) { "true" } else { "false" }
                }
            }
        }

        Set-WslContent -Distribution $Distro -Sudo -Path $wslConfPath -Content ($wsl | ConvertTo-IniContent)

        if ($Restart) {
            # See The 8 Second Rule: https://docs.microsoft.com/en-us/windows/wsl/wsl-config#the-8-second-rule
            wsl --terminate $distro

            # There's a bug in wsl, it's outputting nulls after every character
            while ((Invoke-Wsl --list --running --quiet) -eq $distro) {
                Start-Sleep -Milliseconds 50
            }

            # start it back up, hopefully it'll loose the /etc/resolv.conf
            wsl --distribution $distro echo hello
        }
    }
}

function Update-WslUbuntu {
    <#
        .SYNOPSIS
            Install pwsh in Ubuntu 18.04 or higher.
        .DESCRIPTION
            Installs pwsh from the Microsoft package repository.
            Only works for supported versions of Ubuntu >= 18.04

        .LINK
            https://learn.microsoft.com/en-us/powershell/scripting/install/install-ubuntu
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSPossibleIncorrectUsageOfRedirectionOperator', '')]
    param(
        # The distribution to install into
        [Parameter(Position = 0)]
        [string[]]$Distribution = $(Invoke-Wsl --list --quiet | Where-Object { $_ -match "^ubuntu" })
    )
    foreach($Distro in $Distribution) {
        Write-Verbose "Run aptitude safe-upgrade for $distro"

        # I did not bother asking you for permission to do this.
        # Aptitude is better. Just use that, even though it takes 22Mb
        if (!(Invoke-Wsl --distribution $distro which aptitude 2>$null)) {
            wsl -d $Distribution -u root apt update
            wsl -d $Distribution -u root apt install -y aptitude
        }

        # Update the list of packages
        wsl -d $Distribution -u root aptitude update
        # Install pre-requisite packages.
        wsl -d $Distribution -u root aptitude safe-upgrade -y
    }
}

function Install-WslSshAgentPipe {
    <#
        .SYNOPSIS
            Install npiperelay and socat and configure SSH_AUTH_SOCK forwarding
        .DESCRIPTION
            Configures forwarding for SSH Agent socket, so your linux SSH can use your Windows SSH Agent.

            Specifically, this allows you to use KeePass with KeeAgent to manage your SSH Keys.
    #>
    [CmdletBinding()]
    param(
        # The distribution to connect the pipe to
        [Parameter(Position = 0)]
        [string[]]$Distribution = $(Invoke-Wsl --list --quiet | Where-Object { $_ -notmatch "^docker|-data$" }),

        # The user for whom .bashrc should be modified
        # Defaults to your username all lowercase
        [Parameter(ParameterSetName = "Insecure")]
        $Username = $Env:USERNAME.ToLower(),

        # Ingore chocolatey for install (winget must be available).
        [switch]$NoChocolate
    )

    foreach ($distro in $Distribution) {
        Write-Verbose "Install ssh for $distro"
        # Install npiperelay
        if (!(Get-Command npiperelay.exe -ErrorAction Ignore)) {
            if (-not $NoChocolate -and (Get-Command choco -ErrorAction Ignore)) {
                choco upgrade npiperelay -y
            } elseif (Get-Command winget -ErrorAction Ignore) {
                winget install --id=jstarks.npiperelay -e --accept-source-agreements
            } else {
                throw "Unable to install. Please download https://github.com/jstarks/npiperelay/releases/latest/download/npiperelay_windows_amd64.zip and extract it somewhere in your PATH"
            }
        }

        # install socat in WSL
        wsl -d $Distribution -u root aptitude install -y socat
        if ($LASTEXITCODE) {
            throw "Unable to install socat. I give up."
        }

        # create the ssh-agent-pipe script in WSL
        # Ensure the carriage returns are correct (and fetch the script, if necessary):
        $script = if (Test-Path $PSScriptRoot\ssh-agent-pipe.sh) {
            (Get-Content $PSScriptRoot\ssh-agent-pipe.sh) -join "`n"
        } else {
            Invoke-RestMethod https://gist.githubusercontent.com/Jaykul/19e9f18b8a68f6ab854e338f9b38ca7b/raw/ssh-agent-pipe.sh
        }
        # escape $ and " so we can pass this through bash
        $script | Set-WslContent -Sudo -Path /usr/local/bin/ssh-agent-pipe

        # Make it executable
        wsl -d $Distribution -u root chmod +x /usr/local/bin/ssh-agent-pipe

        if (-not ((wsl -d $Distribution cat '$HOME/.bashrc') -match "/usr/local/bin/ssh-agent-pipe")) {
            # Add to .bashrc for the specified user
            @(
                "if [ -f /usr/local/bin/ssh-agent-pipe ]; then"
                "  . /usr/local/bin/ssh-agent-pipe"
                "fi"
            ) | Add-WslContent -Path '$HOME/.bashrc'
        }
    }
}

function Install-WslUbuntuPwsh {
    <#
        .SYNOPSIS
            Install pwsh in Ubuntu 18.04 or higher.
        .DESCRIPTION
            Installs pwsh from the Microsoft package repository.
            Only works for supported versions of Ubuntu >= 18.04

        .LINK
            https://learn.microsoft.com/en-us/powershell/scripting/install/install-ubuntu
    #>
    [CmdletBinding()]
    param(
        # The distribution to install into
        [Parameter(Position = 0)]
        [string[]]$Distribution = $(Invoke-Wsl --list --quiet | Where-Object { $_ -match "^ubuntu" })
    )
    foreach ($distro in $Distribution) {
        Write-Verbose "Install pwsh for $distro"
        # Update the list of packages
        wsl -d $distro -u root aptitude update
        # Install pre-requisite packages.
        wsl -d $distro -u root aptitude install -y wget apt-transport-https software-properties-common
        # Download the Microsoft repository GPG keys
        wsl -d $distro -u root -- bash -c 'wget -q "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb"'
        # Register the Microsoft repository GPG keys
        wsl -d $distro -u root dpkg -i packages-microsoft-prod.deb
        # Delete the the Microsoft repository GPG keys file
        wsl -d $distro -u root rm packages-microsoft-prod.deb
        # Update the list of packages after we added packages.microsoft.com
        wsl -d $distro -u root aptitude update
        # Install PowerShell
        wsl -d $distro -u root aptitude install -y powershell
    }
}