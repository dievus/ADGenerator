![MayorSec](/images/mayorsec.PNG)
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M03Q2JN)

# ADGenerator

This script will auto-generate the required users, groups, and permissions necessary for my Movement, Pivoting, and Persistence for Pentesters and Ethical Hackers Course.  You can get it on TCM-Academy using my link at https://academy.tcm-sec.com/courses/movement-pivoting-and-persistence?affcode=770707_4ss-lc9h or on Udemy at https://www.udemy.com/course/movement-pivoting-and-persistence/?referralCode=99A09396FE1258FC3A2A.
# Instructions

In order to generate a functional domain controller and active directory, the listed PowerShell scripts need to be executed in the following order:
- Invoke-ForestDeploy.ps1

```. .\Invoke-ForestDeploy.ps1```

```Invoke-ForestDeploy -DomainName <domain name>```

This will install the Windows Active Directory Domain Services toolset and generate the actual domain.  Follow the instructions on screen, making note of the domain name used as this will be needed later.

- ADGenerator.ps1

```. .\ADGenerator.ps1```

```Invoke-ADGenerator -DomainName <domainname>```

This will generate the appropriate users, groups, permissions, configurations, and misconfigurations needed for the actual course.  


For the nitpickers, yes, some of this code was inspired by other resources.  It's literally how coding works.

Instruction is provided in course on how to utilize the netGen.ps1 script.  A later lesson covers cracking an NTLM hash which uses the included password file.
