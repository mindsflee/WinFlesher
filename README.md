# WinFlesher
<p align="center">
  <img src="https://user-images.githubusercontent.com/61688412/199962640-950f21fe-f929-42f5-ae4b-5e4787a9f1d3.png" alt="WinFlesher"/>
</p>


    WINFLESHER v0.1.0.5 
    MITRE EXPLOITATION FRAMEWORK  
    Written by: Alessandro 'mindsflee' Salzano 
    https://github.com/mindsflee                
                                                                                                                                      
    It is released under Common Development and Distribution License 1.0 
    that can be downloaded here:                                    
    https://opensource.org/licenses/CDDL-1.0  
 

    Invoke-WinFlesher is a post exploitation framework for windows written in powershell. 
    It was created by adapting the exploitation techniques to MITRE and it was meant to be modular.


    PS C:\> . .\Invoke-WinFlesher.ps1
    PS C:\> WFL-check-T1574.009
     [+] WARNING: this system is most likely vulnerable to Path Interception by Unquoted Path!
    ProcessId   : 0
    Name        : Vulnerable Service
    DisplayName : Vuln Service
    PathName    : C:\Program Files\A Subfolder\B Subfolder\C Subfolder\Executable.exe
    StartName   : LocalSystem
    StartMode   : Auto
    State       : Stopped

```diff
+ Download the repository in zip format and import it on your victim machine
+ After unzipped it run on a powershell console:  ". \ Invoke-WinFlesher.ps1"
- WinFlesher was created to be scalable and implementable with more TTP and MITRE modules
- We are looking for collaborators!
```
https://user-images.githubusercontent.com/61688412/199961907-ee8573c5-4373-442e-a072-421917550949.mp4


