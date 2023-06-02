# WSL Helper Functions

These automate configuration we find ourselves repeating on everyone's Windows laptops at work.

Most of the functions were pulled from Joel "Jaykul" Bennett's personal [box-starter](https://github.com/Jaykul/BoxStarter-Boxes/blob/main/10_DevOps/WSL.psm1) or [gists](https://gist.github.com/Jaykul/315f7413752a92997390bf2ef052bc17) or [dotfiles](https://github.com/Jaykul/dotfiles) and put here so we would have one single place to look for them.

## Assumptions

> There was no Jedi so wise that he could not be undone by his own assumptions.
― Claudia Gray, Master and Apprentice

1. You **must** be on WSL v2.
2. Your WSL Linux username should be your Windows username, all lower case. If not, you should pass it to any function with a `-UserName` parameter.
3. You install WSL distros through `Install-WslDistro`
4. You mostly use Ubuntu (and thus, use `apt` for package management)
5. WSL "distros" with names that start with "docker-" or end with "-data" are ignored

Many of these functions will not work when these assumptions are false. Most of these functions do not have alternate logic for dealing with additional Linux distros or package managers yet.

NOTE: Some default values include things which are specific to LoanDepot. These have been done carefully, such that if these functions are run on a personal laptop, the LoanDepot values are irrelevant.

## Getting Started

If you've not used this module before, please make sure to read the [Assumptions](#assumptions) above.

### First things first

We need to make sure you're using the current version of WSL, so you need to run `wsl --update` before anything else. If you check your `wsl --version` you should see the WSL version is 1.2 or higher, and you should see the linux Kernel version 5.15 or higher, and WSLg should be available.

If you have existing wsl distributions installed, check to make sure they are running on WSL 2 by using the `wsl --list --verbose` command. If they are not, remove them with `wsl --unregister $distroname` and install new copies.

```bash
wsl --update
wsl --version
wsl --list --verbose
```

## Installing WSL Tools

tl;dr:

Import the module and run these commands in PowerShell on Windows:

```powershell
Install-WslDistro -Default
Update-WslCertificates -Verbose
wsl ping google.com -c3 || Update-WslDns -Verbose
Update-WslUbuntu
Install-WslPowerShellSnap
Install-WslKubectlSnap
```

### Update WSL

See [first things first](#first-things-first) above.

### Install ubuntu

```powershell
Install-WslDistro
```

If you're running this by hand, you'll be prompted for a password, which you'll need to remember whenever you need to `sudo` to run something as root...

### Copy private CA certificates

If you are using a private (internal) CA that's basically self-signed, or if you're using ZScaler (with it's self-signed certificate) then you need to add those CA certificates to WSL's trust list. You can pass a list of their thumbprints to `Update-WslCertificates`.

If you look at the default value, I wrote this so it works for LoanDepot with _no parameters_, but you just need to run something like:

```powershell
Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -Match "ZScaler" | Update-WslCertificates
```

### Make sure your network is working

We've had frequent problems with networking. Particularly, older versions of AnyConnect break WSL networking and requires the VPN to be reconfigured to work correctly. ZScaler Private Access works properly for us, but still somehow breaks Window's ability to configured DNS for WSL.

Test with: `wsl ping google.com` -- if that does not work, try with `wsl ping 8.8.8.8`.

If you can't connect at all, you'll need to disconnect your VPN, and possibly restart WSL -- you can quickly `wsl --terminate ubuntu` and then check with `wsl --list --running` to ensure it's stopped before you re-run the ping commands.

If you can ping the ip address but not the domain name, then you just need to fix your WSL Dns.

```powershell
Update-WslDns
```

**Important:** this disables and replaces the automated configuration. You will probably need to re-run this command whenever you change the network that you're connected to.

### Update Linux

Since WSL distros are not included in Windows Update, you periodically need to update the software in them -- including _right after install_. Run:

```powershell
Update-WslUbuntu
```

Note that this installs and uses `aptitude` because it's a better experience than using apt-get or apt.
The other `Install` functions depend on this (unless they say "Snap"), and will call it to ensure aptitude is installed.

### Installing additional tools.

There are a lot of ways to install our tools like powershell, kubectl, and helm.
Now that WSL 2 supports systemd, Ubuntu in WSL supports snap, which makes that _by far_ the simplest way to install things.
We still have wrapper scripts for a few pieces of this, but you can probably just `sudo snap install ...`


#### Install PowerShell on Linux:

If you need to use PowerShell scripts in linux, or are more comfortable with pwsh than with bash, you will want to install it:

```powershell
Install-WslUbuntuPwsh
```

#### Install SSH Agent forwarding:

If you frequently connect via `ssh` and have configured the Windows OpenSSH Agent service, or KeePass and KeeAgent, or some other agent, you'll want to configure SSH Agent forwarding using socat:

```powershell
Install-WslSshAgentPipe
```

#### Install Kubernetes tools

This function installs kubelogin (for azure), kubectl, and helm, and needs to be updated each release to install the specific (old) version of kubectl we need for working with our "stable" AKS clusters in Azure.

```powershell
Install-WslK8sTools
```

## CAUTION:

Every time Microsoft makes significant changes to WSL, some of these functions become unnecessary, and others break.

Today is May 20, 2023, and our oldest desktops are running Windows 10.0.19042.

The current version of PowerShell is 7.3.4

The current version of Ubuntu in WSL is 20.04

