# ADGenerator

This script will auto-generate the required users, groups, and permissions necessary for my upcoming domain pivoting course. 

# Instructions

In order to generate a functional domain controller and active directory, the listed PowerShell scripts need to be executed in the following order:
- Invoke-ForestDeploy.ps1

```. .\Invoke-ForestDeploy.ps1```

```Invoke-ForestDeploy```

This will install the Windows Active Directory Domain Services toolset and generate the actual domain.  Follow the instructions on screen, making note of the domain name used as this will be needed later.

- ADGenerator.ps1

```. .\ADGenerator.ps1```

```Invoke-ADGenerator```

This will generate the appropriate users, groups, permissions, configurations, and misconfigurations needed for the actual course.  


For the nitpickers, yes, some of this code was inspired by other resources.  It's literally how coding works.
