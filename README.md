# Analyzing a Denuvo bypass approach based on virtualization.

[![](Analyzing_a.png)](Analyzing_a.png)

Hello everyone, since lately there has been a surge of hypervisor-based releases that aim to bypass Denuvo’s DRM, I decided to make a pretty short technical write-up describing what this approach looks like and how it works from a technical perspective.  
  
This write-up is brought to you by _Natasha_ (0x80000003)  
  
Big thanks to :  
  
`*********` - for releasing the bypass for Resident Evil : Requiem  
`Momo5502` - EPT hooks detection analysis ( )  
`SinaKarvandi` - Research on Hypervisors and Development of HyperDBG ([SinaKarvandi - Overview](https://github.com/SinaKarvandi/)) ([https://github.com/SinaKarvandi/Hypervisor-From-Scratch](https://github.com/SinaKarvandi/Hypervisor-From-Scratch))  

**Important Notes** : This article is written for educational purposes only. I do NOT condone nor support the analysis, bypassing, cracking of games (whether Denuvo protected or not) and I do NOT support piracy in any way. Please support the developers that worked really hard on these games and protections (We love you Blaukovitch <3).  
  
This article serves more or so to analyze this bypass approach and how to circumvent it on Denuvo’s side.

## Why this method was chosen :

Why was this method chosen in the first place?

The main reason is that it is a relatively low-effort way to get a protected title running without doing a full reverse engineering effort against the protection itself. It can be shipped quickly, which matters because early release timing can impact sales in the first week.

But this comes at the price of bad performance, instability, security concerns and many other issues.

## Introduction :

In this write-up, we will analyze the main bypass dll from the recent Resident Evil : Requiem release on [cs.rin.ru](http://cs.rin.ru) and go into details on how hypervisor-based debuggers such as HyperDBG can be used to spoof hardware values and in effect allow for a Denuvo DRM bypass.

## Requirements and constraints :

For this approach to work, core Windows kernel protections typically need to be weakened so an unsigned or non-standard kernel driver can be loaded.

Commonly mentioned requirements in public releases include:

-   Disabling Driver Signature Enforcement (DSE).

-   Disabling PatchGuard.

-   Disabling Windows Defender

-   At this point disable windows just for the game to run XD

## Analyzing Resident Evil : Requiem Hypervisor dll :

### 0) Initial load :

In the sample shown here, `amd_ags_x64.dll` \[4\] is replaced with a patched proxy dll included in the release. The proxy dll then loads:

-   The main bypass dll.

-   The original legitimate AMD GPU Services SDK dll \[4\], renamed as `amd_ags_x64.org`.

[![](image.png)](image.png)

[![](image%201.png)](image%201.png)

Since the bypass dll is set as a static import, it will be loaded automatically by the Windows loader without needing a separate injector.

### 1) Hypervisor back-end selection (Intel / AMD) :

Once the main bypass dll is present, it selects the hypervisor back-end based on CPU vendor.

The CPUID vendor string is read and a back-end is selected based on the vendor’s ID.

In the sample:

-   `"AuthenticAMD"` → `SimpleSvm.sys` \[1\]

-   `"GenuineIntel"` → `hyperkd.sys` \[2\]

[![](image%202.png)](image%202.png)

### 2) Service creation and driver start :

After selecting the driver, a service is created and started for that driver.

Because hardware virtualization is typically exclusive, the logic often includes checks to ensure no other hypervisor is already occupying VT-x or AMD-V. If one is present, it may be stopped so the chosen driver can initialize.

Some screenshots of this logic :  

[![](image.jpg)](image.jpg)

[![](image%203.png)](image%203.png)

### 3) Resolving syscall numbers from ntdll :

Syscall numbers are taken from `ntdll.dll` and are then used in other functions.

[![](image%204.png)](image%204.png)

### 4) IAT hooking :

IAT hooking is used to redirect selected imports in the game’s executable.  
  
Hooked imports are : `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `user32.dll`

[![](image%205.png)](image%205.png)

[![](image%206.png)](image%206.png)

[![](image%207.png)](image%207.png)

[![](image%208.png)](image%208.png)

With the IAT patched, calls that would normally go directly to these modules are routed through the bypass dll’s handlers.

### 5) License file / Token handling :

Inside the main bypass dll, there are 2 different pre-generated tokens that are assigned depending on the host’s CPU architecture and the corresponding hypervisor (as shown below). These tokens are written to a .bin file on first launch and are then used by the hypervisor as Denuvo tokens.  

[![](image(2).jpg)](image\(2\).jpg)

###   
  
Small Notes :

-   Detanup01’s GBE fork was used to load the game and also emulate steam API services \[10\].

-   HyperEvade was used to also further hide the hypervisor (I will talk about this more later).  
    

[![](image%209.png)](image%209.png)

The CPU brand string in the sample I analyzed is set to `DenuvOWO CPU @ 1337 GHz`. XD

[![](image%2010.png)](image%2010.png)

## Let’s dive more into the details! :  

[![](image%2011.png)](image%2011.png)

HyperDBG is a very advanced debugger and thus I won’t analyze every part of it and more or so focus on the main part of hardware spoofing and how it can be done in the context of Denuvo.  
  
All the commands here can be used with HyperDBG’s scripting system for testing. A custom implementation can be done later to optimize this process for an actual bypass release.  
  
Examples :  
[https://docs.hyperdbg.org/commands/scripting-language/debugger-script](https://docs.hyperdbg.org/commands/scripting-language/debugger-script)  
[https://github.com/HyperDbg/scripts](https://github.com/HyperDbg/scripts)

## Hardware Spoofing :

HyperDBG uses the Virtual Machine Control Structure (VMCS) to enable CPUID exiting. This ensures that when the CPUID instruction is executed, the processor pauses and triggers a VM exit, handing control to the hypervisor. This effectively allows for hardware spoofing on very low levels of the system.  
  
So, how is this exactly done inside HyperDBG ? Since HyperDBG doesn’t have a database of all CPUs and their hardware values, we must find out the hardware values for our specific CPU and give them to HyperDBG to do its job. For this, I personally used `coreinfo64.exe` which is available in Windows Sysinternals tools (you can get it from here if you want : [live.sysinternals.com](https://live.sysinternals.com/)). You can also find the same values on Intel’s product page or from a random CPU-Z validator page \[12\]\[13\].

  
We can then use the `!cpuid` command \[5\] to directly spoof our CPU values!

### Spoofing basic CPUID values \[8\] :

For this example, I’m going with an i9-11900K.  
The standard signature is typically `0x000A0671`, So, we can simply pass a command to HyperDBG to tell it to overwrite the CPUID to match our CPU.

[![](image%2012.png)](image%2012.png)

Here we’re setting our CPUID to `0x000A0671`and flipping the Hypervisor Present bit to 0 to keep HyperDBG from getting detected.  
  
Now that the CPUID spoofing is done, let’s move to the Brand string.  
  
We have `11th Gen Intel(R) Core(TM) i9-11900K @ 3.50GHz.`

The whole string is 48 bytes long and so we must break it into 3 segments of 16 bytes each. (The same as shown in the actual bypass release)  
  
**Note** : Pretty sure we can change this value to whatever we want although I’m not sure.

[![](image%2013.png)](image%2013.png)

Now that is this done, let’s move to spoofing the values in the specific leaves to ensure that they match our CPU \[14\].  
  
Check out the CPUID wikipedia page where they mention all mappings of cpuid leaves :  
[https://en.wikipedia.org/wiki/CPUID#](https://en.wikipedia.org/wiki/CPUID#)

### Spoofing Extended Feature Flags (Leaf 0x7) :

There’s a lot more to spoof to ensure that the CPU matches perfectly, we can’t take risks with checks so we have to be careful about all the different values that represent a CPU.  
  
Let’s start by spoofing extended feature flags \[6\]. I’ll continue with my CPU of i9-11900K.

[![](image%2014.png)](image%2014.png)

This leaf (0x7 / 0) is used to check if your CPU supports specific security or performance features. If you’re on an older model and these flags mismatch, it might cause some issues.

### Spoofing Cache Parameters (Leaf 0x4) \[7\]:

An i9-11900K has 16MB of Cache, let’s spoof that value to match our CPU. For this, we must spoof the value on all sub-leafs of Leaf 0x4 and they must all match.  

[![](image%2015.png)](image%2015.png)

Okay, now that that is done, let’s keep going.

### Spoofing Topology (Leaf 0xB and 0x1F) \[9\] :

Since Topology Enumeration can be used to know how many logical processors and cores actually exist, we can also spoof these values to match our CPU.

[![](image%2016.png)](image%2016.png)

Now we’re fully done with spoofing our CPU values and we’re good to go.

### Spoofing Storage and Disk serials :

After finishing up with spoofing the CPU values, let’s move to the rest of the hardware, starting with Storage and Disk serials.  
  
For this, let’s use the `!syscall` command to spoof the storage serial id.  
  
The specific syscall that we have to spoof here is `NtDeviceIoControlFile`, which is commonly used by user-mode code to request disk/device information.

**Note** : `IOCTL_STORAGE_GET_DEVICE_NUMBER` does not return serial numbers; serial/model information is typically queried through other storage IOCTLs (for example via `IOCTL_STORAGE_QUERY_PROPERTY` / `StorageDeviceProperty`), so those are the requests you’d generally need to intercept if the goal is serial spoofing.  

[![](image%2017.png)](image%2017.png)

### Spoofing Windows build number :

Let’s now spoof the Windows build number, as always, make sure it matches the value used to generate the Denuvo token.  
  
Here I’m going to use the `!epthook` command to spoof the `NtBuildNumber` in `KUSER_SHARED_DATA`, this command can also be used to spoof all the different values in `KUSER_SHARED_DATA`.

[![](image%2018.png)](image%2018.png)

**Note** : There are many other values that should be spoofed in `KUSER_SHARED_DATA` , If I mention all of them here the article will turn into a 20 page manual on details of `KUSER_SHARED_DATA`

### Spoofing GPU vendor ID :

Now onto spoofing the GPU, for this, I’ll be using the `!epthook` command to modify various different values.  
  
In this example, I’m spoofing my GPU to an `AMD Radeon RX 6800 XT`. (to understand more about the PCIe Configuration Space please check out AMD’s documentation : [https://docs.amd.com/r/en-US/pg343-pcie-versal/Configuration-Space](https://docs.amd.com/r/en-US/pg343-pcie-versal/Configuration-Space))  
  
For this, I’m going to spoof 5 different values, which are the `Vendor ID`, `Device ID`, `Revision ID`, `Subsystem Vendor ID` and `Subsystem ID` .  

[![](image%2019.png)](image%2019.png)

[![](image%2020.png)](image%2020.png)

### Better stealth :

HyperDBG has the option for Transparent Mode (RDTSC spoofing and other functions…), which we can enable through the `!hide` command. This will spoof the time that the function took to run to help evade some checks.  
  
You can also use HyperEvade \[11\], but I won’t be documenting that here.

### Important Note :

Denuvo checks for many other values in `KUSER_SHARED_DATA` , `WinAPI` and many other checks pre and post OEP (Original Entry Point for those who don’t know). Want to find them ? Suit yourself and analyze the protection like a normal human being instead of trying to find “vulnerabilities” to bypass it. Though I’d like to say that all of Denuvo DRM checks can be bypassed this way (As of February 2026).

## SimpleSVM :

SimpleSVM is used as a hypervisor for AMD based cpus. While I was hesitant to talk about it here, I decided to mention it lightly anyway :)  
  
SimpleSVM is still very experimental compared to HyperDBG. Thus the source code must be modified to actually implement some of the spoofs that I talked about earlier. The documentation is also barely there so you have to go with the good old source code analysis to understand most of what is the hypervisor is doing (Luckily, tandasat, the developer of SimpleSVM, commented most of the code to explain what it’s doing).  
  
I won’t go into detail on implementing every spoofing as it’s a case by case approach and also because I have to basically modify large parts of the SimpleSVM project just to allow for such stuff to happen but I’d like to mention that there are many differences between Intel and AMD and in some cases it allows for AMD hypervisors to be more detectable ;)

## Detecting Hypervisor bypass attempts :

Now let’s talk about Denuvo’s favorite part of this article. :3  
  
The various techniques to detect hypervisor bypass attempts and patching such methods.  
  
To be honest, there isn’t much to do on user mode level (that I can talk about here / publicly), thus a custom driver would need to be implemented to add most of these checks.  
  
In this section I will discuss general techniques to detect hypervisors, I will later on explain why some stuff won’t work in the case of Denuvo.

### EPT hook detection :

We can use different EPT hook detection techniques \[15\] to detect any hooks on EPT level. This will break spoofing GPU values in HyperDBG as that method relies on EPT hooks.  
  
The methods here are discussed and documented by Momo5502 here : [https://momo5502.com/posts/2022-05-02-detecting-hypervisor-assisted-hooking/](https://momo5502.com/posts/2022-05-02-detecting-hypervisor-assisted-hooking/)  
  
This includes a Timing Check, Thread Check and a Write Check which Momo has provided the source code of \[16\].  
  
I won’t go ahead and re-explain what he already explained in his article, go check him out! \[15\]  
  
**Note** : As stated before RDTSC spoofing has been implemented in HyperDBG making momo’s timing check useless.

### Enforcing DSE on :

Like many other DRMs (such as Byfron), DSE could be enforced to make sure that the game wouldn’t run under Windows Test Mode. Since unsigned drivers can’t run, the main `hyperkd.sys` driver and `SimpleSVM.sys` will fail to work.

### Timing Checks :

While timing checks seem like a good idea especially knowing that the Hypervisor has to make vmexits on multiple functions, it is unreliable and can be very noisy which could lead to false positives.  
  
With that being said, I don’t recommend timing checks as a solution as it will cause issues and can be spoofed with a hardened enough spoofing implementation.

### Explaining the current Denuvo situation :

There are many checks that can be used to detect hypervisors, but the issue is most of them can be spoofed one way or another. Checks that must be used have to be very reliable and very hard to spoof.  
  
An obvious check is already implemented in the bypass dll itself.  

[![](image%2021.png)](image%2021.png)

Here the dll checks for the Microsoft Hyper-V interface signature using cpuid, and Denuvo could theoretically just start checking every cpuid value and using it for token generation, but that would just end up with another cat and mouse game where Denuvo adds more checks and hypervisor releases keep adding more spoofs which is not reliable at all as a long term solution for hypervisors.  
  
Timing checks are unreliable and thus those also cannot be used.  
  
The solution that Denuvo will use needs to be :  
  
\- Reliable.  
\- Not easy to bypass.  
\- Doesn’t affect performance.  
\- Doesn’t rely on a kernel driver.  
\- Doesn’t ruin the experience for people that actually bought the game.

### Overkill Approaches :

An overkill approach for detecting such Hypervisors would be to either :  
  
\- Run the whole game in a hypervisor from the start, which in cases such as Denuvo wouldn’t be efficient at all due to performance issues and would cause heavy backlash from the community. This will never happen due to hardware support. (This would also cause just another SecuROM case).  
  
\- Implement a kernel driver level detection for all different kinds of anti-analysis purposes which serves to detect both Hypervisors and improve overall DRM effectiveness. (Denuvo already has its own kernel level anti-cheat so this won’t be a hard implementation for them). This will probably not happen due to support for proton.

## Finishing up :

After we’re done, we can go ahead and generate the Denuvo token matching our CPU (if you have the CPU) or simply generate a new Denuvo token for these specific values in a VM or some kind of Hypervisor (figure it out yourself, there’s a million approaches for this). Though I would recommend that you generate it inside an environment with these values and then use the same values from the environment to avoid any problems with the bypass.

[![](konata-konata-happy.png)](konata-konata-happy.png)

## Summary :

When the game is ran, a custom bypass dll is loaded to attach a hypervisor layer that could be used to spoof various values that are checked by Denuvo, this implementation allows the user to run the game under an already generated token configured to the hypervisor environment.

## Closing statement :

From a purely technical standpoint, this is a pretty cool approach, but I personally don’t think any crack/bypass release of any game should contain code that requires kernel-level access and attaches itself to very low level layers just to operate, especially at the cost of performance and security concerns. Instead of wasting your time with this, study the protection and try to analyze it yourself from a research perspective.

## References / Sources :

  
Please check out some of the projects and topics that I talked about in this analysis.  
  
Knowledge of Intel CPU architecture is needed to understand some of the topics in this article, check out Intel’s CPU manuals (specifically “Intel (R) 64 and IA-32 Architectures Software Developer’s Manual Combined Volumes: 1, 2A, 2B, 2C, 2D, 3A, 3B, 3C, 3D, and 4”) (I basically had to read half of this manual for this article XD) : [https://cdrdv2.intel.com/v1/dl/getContent/671200](https://cdrdv2.intel.com/v1/dl/getContent/671200)  
  
Check out this paper to understand more about HyperDBG and its different usages and functions :  
[https://scispace.com/pdf/hyperdbg-reinventing-hardware-assisted-debugging-extended-2qr0u9qm.pdf](https://scispace.com/pdf/hyperdbg-reinventing-hardware-assisted-debugging-extended-2qr0u9qm.pdf)  
  
Check out AMD’s documentation on PCIe Configuration Space : [https://docs.amd.com/r/en-US/pg343-pcie-versal/Configuration-Space](https://docs.amd.com/r/en-US/pg343-pcie-versal/Configuration-Space)  
  
Learn about CPUID : [https://en.wikipedia.org/wiki/CPUID](https://en.wikipedia.org/wiki/CPUID)  
  
\[1\] SimpleSVM : [https://github.com/tandasat/SimpleSvm](https://github.com/tandasat/SimpleSvm)  
\[2\] HyperDBG : [https://doxygen.hyperdbg.org/index.html](https://doxygen.hyperdbg.org/index.html)  
\[3\] HyperDBG’s Hyperkd : [https://doxygen.hyperdbg.org/dir\_fd401680aa8c7ceffc479e97f6bdc4df.html](https://doxygen.hyperdbg.org/dir_fd401680aa8c7ceffc479e97f6bdc4df.html)  
\[4\] amd\_ags\_x64.dll : [https://www.dllme.com/dll/files/amd\_ags\_x64](https://www.dllme.com/dll/files/amd_ags_x64)  
\[5\] HyperDBG !cpuid documentation : [https://docs.hyperdbg.org/commands/extension-commands/cpuid](https://docs.hyperdbg.org/commands/extension-commands/cpuid)  
\[6\] Wikipedia CPUID Extended Features leaf : [https://en.wikipedia.org/wiki/CPUID#EAX=7,\_ECX=1:\_Extended\_Features](https://en.wikipedia.org/wiki/CPUID#EAX=7,_ECX=1:_Extended_Features)  
\[7\] Wikipedia CPUID Intel Thread / Core and cache topology leaf : [https://en.wikipedia.org/wiki/CPUID#EAX=4\_and\_EAX=Bh:\_Intel\_Thread/Core\_and\_Cache\_Topology](https://en.wikipedia.org/wiki/CPUID#EAX=4_and_EAX=Bh:_Intel_Thread/Core_and_Cache_Topology)  
\[8\] Wikipedia Basic CPUID values leaf : [https://en.wikipedia.org/wiki/CPUID#EAX=0:\_Highest\_Function\_Parameter\_and\_Manufacturer\_ID](https://en.wikipedia.org/wiki/CPUID#EAX=0:_Highest_Function_Parameter_and_Manufacturer_ID)  
\[9\] Intel 64 Architecture Processor Topology Enumeration (Page 14) : [https://www.intel.com/content/www/us/en/content-details/775917/intel-64-architecture-processor-topology-enumeration-technical-paper.html](https://www.intel.com/content/www/us/en/content-details/775917/intel-64-architecture-processor-topology-enumeration-technical-paper.html)  
\[10\] Detanup01’s GBE fork : [https://github.com/Detanup01/gbe\_fork](https://github.com/Detanup01/gbe_fork)  
\[11\] Learn about HyperEvade : [https://fosdem.org/2026/events/attachments/CDPRDX-invisible\_hypervisors\_debugging\_with\_hyperdbg/slides/266821/hyperevad\_lyhtmgy.pdf](https://fosdem.org/2026/events/attachments/CDPRDX-invisible_hypervisors_debugging_with_hyperdbg/slides/266821/hyperevad_lyhtmgy.pdf)  
\[12\] i9-11900K CPU Specifications : [https://www.intel.com/content/www/us/en/products/sku/212325/intel-core-i911900k-processor-16m-cache-up-to-5-30-ghz/specifications.html](https://www.intel.com/content/www/us/en/products/sku/212325/intel-core-i911900k-processor-16m-cache-up-to-5-30-ghz/specifications.html)  
\[13\] i9-11900K CPU Specifications from a random dude on CPU-Z validator : [https://valid.x86.fr/8n2zgs](https://valid.x86.fr/8n2zgs)  
\[14\] Detailed mapping of CPUID identification : [https://www.felixcloutier.com/x86/cpuid](https://www.felixcloutier.com/x86/cpuid)

\[15\] EPT hook detection techniques by Momo5502 : [https://github.com/momo5502/ept-hook-detection](https://github.com/momo5502/ept-hook-detection)  
\[16\] Momo5502 Github repository on EPT hooking detection : [https://github.com/momo5502/ept-hook-detection](https://github.com/momo5502/ept-hook-detection)
