![MayorSec](/images/mayorsec.PNG)
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M03Q2JN)

# ADGenerator

This script will auto-generate the required users, groups, and permissions necessary for my Movement, Pivoting, and Persistence for Pentesters and Ethical Hackers Course.  You can get it on TCM-Academy using my link at https://academy.tcm-sec.com/courses/movement-pivoting-and-persistence?affcode=770707_4ss-lc9h.
# Instructions

In order to generate a functional domain controller and active directory, the listed PowerShell scripts need to be executed in the following order:
- Invoke-ForestDeploy.ps1

```. .\Invoke-ForestDeploy.ps1```

```Invoke-ForestDeploy -DomainName mayorsec.local```

This will install the Windows Active Directory Domain Services toolset and generate the actual domain.  Follow the instructions on screen, making note of the domain name used as this will be needed later.  The scripts are hardcoded for mayorsec.local, and any deviation from that domain name will likely break the ADGenerator.ps1 functionality.  Making any modifications are on you.

- ADGenerator.ps1

```. .\ADGenerator.ps1```

```Invoke-ADGenerator -DomainName mayorsec.local```

This will generate the appropriate users, groups, permissions, configurations, and misconfigurations needed for the actual course.  

Once all scripts are ran and the workstations are joined, the following needs to be ran on DC01 from an elevated Powershell terminal to generate the unconstrained delegation configuration.

```Get-ADComputer -Identity Workstation-02 | Set-ADAccountControl -TrustedForDelegation $true```


Instruction is provided in course on how to utilize the netGen.ps1 script.  A later lesson covers cracking an NTLM hash which uses the included password file.
