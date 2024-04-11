#include <iostream>
#include "Windows.h"

void authenticator() {
    system("mode 25,7");
    while (true) {
        system("color 1");
        system("cls");
        std::string login, password;
        std::cout << "Login: ";
        std::cin >> login;
        std::cout << "Password: ";
        std::cin >> password;

        if (login == "admin" && password == "admin") {
            system("mode 60,12");
            system("cls");
            system("color a");
            std::cout << "login sucessful...\n";
            system("timeout /t 2");
            break;
        } else {
            system("cls");
            system("color 4");
            std::cerr << "Login or password incorrect" << std::endl;
            system("timeout /t 3");
        }
    }
}

// menus

void mainMenu() {
    system("mode 68,12");
    system("cls");
    system("color 1");

    std::cout << "====================================================================\n";
    std::cout << "[ 1 ] optimize all system (services will be disabled)\n";
    std::cout << "[ 2 ] optimime all system (services will not be disabled)\n";
    std::cout << "[ 3 ] optimize only internet\n";
    std::cout << "[ 4 ] clean up the temporary files\n";
    std::cout << "[ 5 ] download apps options\n";
    std::cout << "[ x ] cancel\n";
    std::cout << "====================================================================\n";
}

void downloadMenu() {
    system("mode 69,16");
    system("cls");
    system("color 1");

    std::cout << "=====================================================================\n";
    std::cout << "[ 1 ] download:  Memory Cleaner\n";
    std::cout << "[ 2 ] download:  Discord\n";
    std::cout << "[ 3 ] download:  Steam\n";
    std::cout << "[ 4 ] download:  GitHub\n";
    std::cout << "[ 5 ] download:  Browsers\n";
    std::cout << "[ 6 ] download:  7zip or WinRar\n";
    std::cout << "[ 7 ] download:  All Visual C++ Version (2005 - 2022)\n";
    std::cout << "[ 8 ] +options:  (system information softwares and more tweaks)\n";
    std::cout << "[ x ] return\n";
    std::cout << "=====================================================================\n";

}

void optionsMenu() {
    system("mode 67,16");
    system("cls");
    system("color 1");

    std::cout << "===================================================================\n";
    std::cout << "[ 1 ] download:  NVCleanInstall\n";
    std::cout << "[ 2 ] download:  NvidiaProfileInspector\n";
    std::cout << "[ 3 ] download:  HWMonitor\n";
    std::cout << "[ 4 ] download:  GPU-Z\n";
    std::cout << "[ 5 ] download:  CCleaner\n";
    std::cout << "[ 6 ] download:  QuickCPU\n";
    std::cout << "[ 7 ] download:  Spotify\n";
    std::cout << "[ 8 ] download:  PhotoShop (Pre-Actived)\n";
    std::cout << "[ 9 ] +options:  FPS packs (fortnite, csgo, valorant, [...])\n";
    std::cout << "[ x ] return\n";
    std::cout << "===================================================================\n";

}

void menuBrowsers() {
    system("mode 45,11");
    system("cls");
    system("color 1");

    std::cout << "=============================================\n";
    std::cout << "[ 1 ] download:  Google Chrome\n";
    std::cout << "[ 2 ] download:  OperaGX\n";
    std::cout << "[ 3 ] download:  Brave\n";
    std::cout << "[ 4 ] download:  Firefox\n";
    std::cout << "[ x ] return\n";
    std::cout << "=============================================\n";
}

void menuRar() {
    system("mode 33,8");
    system("cls");
    system("color 1");

    std::cout << "=================================\n";
    std::cout << "[ 1 ] download:  7zip\n";
    std::cout << "[ 2 ] download:  WinRar\n";
    std::cout << "[ x ] return\n";
    std::cout << "=================================\n";
}

void fpsPacks() {
    system("mode 60,12");
    system("cls");
    system("color 1");

    std::cout << "============================================================\n";
    std::cout << "[ 1 ] download:  minecraft / fps pack (v1.8.9)\n";
    std::cout << "[ 2 ] download:  valorant  / fps pack\n";
    std::cout << "[ 3 ] download:  fortnite  / fps pack\n";
    std::cout << "[ 4 ] download:  csgo      / fps pack\n";
    std::cout << "[ 5 ] download:  pubg      / fps pack\n";
    std::cout << "[ x ] return\n";
    std::cout << "============================================================\n";

}

// optimizations

void optimization1() {
    system("mode 90,50");
    system("cls");

    // usb optimization

    system("powershell.exe -encodedCommand JABkAGUAdgBpAGMAZQBzAFUAUwBCACAAPQAgAEcAZQB0AC0AUABuAHAARABlAHYAaQBjAGUAIAB8ACAAdwBoAGUAcgBlACAAewAkAF8ALgBJAG4AcwB0AGEAbgBjAGUASQBkACAALQBsAGkAawBlACAAIgAqAFUAUwBCAFwAUgBPAE8AVAAqACIAfQAgACAAfAAgAA0ACgBGAG8AcgBFAGEAYwBoAC0ATwBiAGoAZQBjAHQAIAAtAFAAcgBvAGMAZQBzAHMAIAB7AA0ACgBHAGUAdAAtAEMAaQBtAEkAbgBzAHQAYQBuAGMAZQAgAC0AQwBsAGEAcwBzAE4AYQBtAGUAIABNAFMAUABvAHcAZQByAF8ARABlAHYAaQBjAGUARQBuAGEAYgBsAGUAIAAtAE4AYQBtAGUAcwBwAGEAYwBlACAAcgBvAG8AdABcAHcAbQBpACAADQAKAH0ADQAKAA0ACgBmAG8AcgBlAGEAYwBoACAAKAAgACQAZABlAHYAaQBjAGUAIABpAG4AIAAkAGQAZQB2AGkAYwBlAHMAVQBTAEIAIAApAA0ACgB7AA0ACgAgACAAIAAgAFMAZQB0AC0AQwBpAG0ASQBuAHMAdABhAG4AYwBlACAALQBOAGEAbQBlAHMAcABhAGMAZQAgAHIAbwBvAHQAXAB3AG0AaQAgAC0AUQB1AGUAcgB5ACAAIgBTAEUATABFAEMAVAAgACoAIABGAFIATwBNACAATQBTAFAAbwB3AGUAcgBfAEQAZQB2AGkAYwBlAEUAbgBhAGIAbABlACAAVwBIAEUAUgBFACAASQBuAHMAdABhAG4AYwBlAE4AYQBtAGUAIABMAEkASwBFACAAJwAlACQAKAAkAGQAZQB2AGkAYwBlAC4AUABOAFAARABlAHYAaQBjAGUASQBEACkAJQAnACIAIAAtAFAAcgBvAHAAZQByAHQAeQAgAEAAewBFAG4AYQBiAGwAZQA9ACQARgBhAGwAcwBlAH0AIAAtAFAAYQBzAHMAVABoAHIAdQANAAoAfQANAAoADQAKACQAYQBkAGEAcAB0AGUAcgBzACAAPQAgAEcAZQB0AC0ATgBlAHQAQQBkAGEAcAB0AGUAcgAgAC0AUABoAHkAcwBpAGMAYQBsACAAfAAgAEcAZQB0AC0ATgBlAHQAQQBkAGEAcAB0AGUAcgBQAG8AdwBlAHIATQBhAG4AYQBnAGUAbQBlAG4AdAANAAoAIAAgACAAIABmAG8AcgBlAGEAYwBoACAAKAAkAGEAZABhAHAAdABlAHIAIABpAG4AIAAkAGEAZABhAHAAdABlAHIAcwApAA0ACgAgACAAIAAgACAAIAAgACAAewANAAoAIAAgACAAIAAgACAAIAAgACQAYQBkAGEAcAB0AGUAcgAuAEEAbABsAG8AdwBDAG8AbQBwAHUAdABlAHIAVABvAFQAdQByAG4ATwBmAGYARABlAHYAaQBjAGUAIAA9ACAAJwBEAGkAcwBhAGIAbABlAGQAJwANAAoAIAAgACAAIAAgACAAIAAgACQAYQBkAGEAcAB0AGUAcgAgAHwAIABTAGUAdAAtAE4AZQB0AEEAZABhAHAAdABlAHIAUABvAHcAZQByAE0AYQBuAGEAZwBlAG0AZQBuAHQADQAKACAAIAAgACAAIAAgACAAIAB9AA==");

    // sc optimizations

    system("sc stop DiagTrack");
    system("sc stop diagnosticshub.standardcollector.service");
    system("sc stop dmwappushservice");
    system("sc stop RemoteRegistry");
    system("sc stop TrkWks");
    system("sc stop WMPNetworkSvc");
    system("sc stop SysMain");
    system("sc stop lmhosts");
    system("sc stop VSS");
    system("sc stop RemoteAccess");
    system("sc stop iphlpsvc");
    system("sc stop DoSvc");
    system("sc stop SEMgrSvc");
    system("sc stop BDESVC");
    system("sc stop SstpSvc");
    system("sc stop HomeGroupListener");
    system("sc stop HomeGroupProvider");
    system("sc stop lfsvc");
    system("sc stop NetTcpPortSharing");
    system("sc stop SharedAccess");
    system("sc stop WbioSrvc");
    system("sc stop WMPNetworkSvc");
    system("sc stop wisvc");
    system("sc stop TapiSrv");
    system("sc stop SmsRouter");
    system("sc stop SharedRealitySvc");
    system("sc stop ScDeviceEnum");
    system("sc stop SCardSvr");
    system("sc stop RetailDemo");
    system("sc stop PhoneSvc");
    system("sc stop perceptionsimulation");
    system("sc stop BTAGService");
    system("sc stop AJRouter");
    system("sc stop CDPSvc");
    system("sc stop ShellHWDetection");
    system("sc stop DusmSvc");
    system("sc stop BthAvctpSvc");
    system("sc stop BITS");
    system("sc stop DPS");
    system("sc config DiagTrack start= disabled");
    system("sc config diagnosticshub.standardcollector.service start= disabled");
    system("sc config dmwappushservice start= disabled");
    system("sc config RemoteRegistry start= disabled");
    system("sc config TrkWks start= disabled");
    system("sc config WMPNetworkSvc start= disabled");
    system("sc config SysMain start= disabled");
    system("sc config lmhosts start= disabled");
    system("sc config VSS start= disabled");
    system("sc config RemoteAccess start= disabled");
    system("sc config iphlpsvc start= disabled");
    system("sc config DoSvc start= disabled");
    system("sc config SEMgrSvc start= disabled");
    system("sc config BDESVC start= disabled");
    system("sc config SstpSvc start= disabled");
    system("sc config HomeGroupListener start= disabled");
    system("sc config HomeGroupProvider start= disabled");
    system("sc config lfsvc start= disabled");
    system("sc config NetTcpPortSharing start= disabled");
    system("sc config SharedAccess start= disabled");
    system("sc config WbioSrvc start= disabled");
    system("sc config WMPNetworkSvc start= disabled");
    system("sc config wisvc start= disabled");
    system("sc config TapiSrv start= disabled");
    system("sc config SmsRouter start= disabled");
    system("sc config SharedRealitySvc start= disabled");
    system("sc config ScDeviceEnum start= disabled");
    system("sc config SCardSvr start= disabled");
    system("sc config RetailDemo start= disabled");
    system("sc config PhoneSvc start= disabled");
    system("sc config perceptionsimulation start= disabled");
    system("sc config BTAGService start= disabled");
    system("sc config AJRouter start= disabled");
    system("sc config CDPSvc start= disabled");
    system("sc config ShellHWDetection start= disabled");
    system("sc config DusmSvc start= disabled");
    system("sc config BthAvctpSvc start= disabled");
    system("sc config BITS start= demand");
    system("sc config DPS start= disabled");

    // services optimizations

    system("schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\ProgramDataUpdater\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\StartupAppTask\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\Autochk\\Proxy\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\Maintenance\\WinSAT\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\SystemRestore\\SR\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Office\\Office Automatic Updates 2.0\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Office\\Office ClickToRun Service Monitor\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Office\\Office Feature Updates\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Office\\Office Feature Updates Logon\" /Disable");
    system("schtasks /Change /TN \"\\Microsoft\\Windows\\Power Efficiency Diagnostics\\AnalyzeSystem\" /Disable");
    system("schtasks /Change /TN \"MicrosoftEdgeUpdateTaskMachineCore\" /Disable");
    system("schtasks /Change /TN \"MicrosoftEdgeUpdateTaskMachineUA\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\FileHistory\\File History (maintenance mode)\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\CloudExperienceHost\\CreateObjectTask\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\DiskFootprint\\Diagnostics\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\NetTrace\\GatherNetworkInfo\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\PI\\Sqm-Tasks\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\Time Synchronization\\ForceSynchronizeTime\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\Time Synchronization\\SynchronizeTime\" /Disable");
    system("schtasks /Change /TN \"Microsoft\\Windows\\Windows Error Reporting\\QueueReporting\" /Disable");

    // dism optimizations

    system("DISM.exe /online /norestart /Enable-Feature /FeatureName:\"NetFx3\"");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:SimpleTCP /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:Windows-Identity-Foundation /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:DirectoryServices-ADAM-Client /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WebServerRole /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WebServer /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-CommonHttpFeatures /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HttpErrors /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HttpRedirect /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ApplicationDevelopment /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-NetFxExtensibility /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-NetFxExtensibility45 /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HealthAndDiagnostics /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HttpLogging /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-LoggingLibraries /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-RequestMonitor /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HttpTracing /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-Security /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-URLAuthorization /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-RequestFiltering /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-IPSecurity /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-Performance /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HttpCompressionDynamic /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WebServerManagementTools /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ManagementScriptingTools /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-IIS6ManagementCompatibility /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-Metabase /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:WAS-WindowsActivationService /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:WAS-ProcessModel /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:WAS-NetFxEnvironment /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:WAS-ConfigurationAPI /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HostableWebCore /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-CertProvider /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WindowsAuthentication /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-DigestAuthentication /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ClientCertificateMappingAuthentication /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-IISCertificateMappingAuthentication /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ODBCLogging /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-StaticContent /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-DefaultDocument /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-DirectoryBrowsing /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WebDAV /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WebSockets /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ApplicationInit /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ASPNET /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ASPNET45 /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ASP /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-CGI /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ISAPIExtensions /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ISAPIFilter /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ServerSideIncludes /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-CustomLogging /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-BasicAuthentication /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HttpCompressionStatic /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ManagementConsole /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ManagementService /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WMICompatibility /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-LegacyScripts /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-LegacySnapIn /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-FTPServer /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-FTPSvc /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-FTPExtensibility /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-Container /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-Server /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-Triggers /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-ADIntegration /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-HTTP /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-Multicast /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-DCOMProxy /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-HTTP-Activation45 /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-TCP-Activation45 /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-Pipe-Activation45 /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-MSMQ-Activation45 /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-HTTP-Activation /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-NonHTTP-Activation /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:NetFx4Extended-ASPNET45 /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:MediaPlayback /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:Printing-XPSServices-Features /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:MSRDC-Infrastructure /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:TelnetClient /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:TFTP /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:TIFFIFilter /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:WorkFolders-Client /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:SMB1Protocol /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:Microsoft-Hyper-V-All /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:Microsoft-Hyper-V-Tools-All /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:Microsoft-Hyper-V /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:Microsoft-Hyper-V-Management-Clients /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:Microsoft-Hyper-V-Management-PowerShell /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-TCP-PortSharing45 /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:SmbDirect /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:Printing-Foundation-Features /Remove");
    system("DISM.exe /Online /norestart /Disable-Feature /featurename:Printing-Foundation-InternetPrinting-Client /Remove");
    system("DISM.exe /Online /norestart /Remove-Capability /CapabilityName:App.StepsRecorder~~~~0.0.1.0");
    system("DISM.exe /Online /norestart /Remove-Capability /CapabilityName:App.Support.QuickAssist~~~~0.0.1.0");
    system("DISM.exe /Online /norestart /Remove-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0");
    system("DISM.exe /Online /norestart /Remove-Capability /CapabilityName:Hello.Face.20134~~~~0.0.1.0");
    system("DISM.exe /Online /norestart /Remove-Capability /CapabilityName:MathRecognizer~~~~0.0.1.0");
    system("DISM.exe /Online /norestart /Remove-Capability /CapabilityName:Media.WindowsMediaPlayer~~~~0.0.12.0");
    system("DISM.exe /Online /Set-ReservedStorageState /State:Disabled");

    // power configs optimization 

    system("powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61");
    system("powercfg -h off");
    system("powercfg.exe -change -monitor-timeout-dc 0");
    system("powercfg.exe -change -standby-timeout-dc 0");
    system("powercfg.exe -change -hibernate-timeout-dc 0");
    system("powercfg.exe -change -monitor-timeout-ac 0");
    system("powercfg.exe -change -standby-timeout-ac 0");
    system("powercfg.exe -change -hibernate-timeout-ac 0");
    system("powercfg -SETDCVALUEINDEX SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 0");
    system("powercfg -SETACVALUEINDEX SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 0");
    system("powercfg -SETACVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0");
    system("powercfg -SETDCVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 3");
    system("powercfg -SETACVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3");
    system("powercfg -SETDCVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3");
    system("powercfg -SETDCVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0");
    system("powercfg -SETACVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0");
    system("bcdedit /set tscsyncpolicy Enhanced");
    system("bcdedit /deletevalue useplatformclock");
    system("bcdedit /set disabledynamictick yes");
    system("powershell Disable-NetAdapterLso -Name \"*\"");
    system("powershell \"ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}\"");
    system("powershell \"ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}\"");
    system("cls");

    // internet optimization

    system("ipconfig /flushdns");
    system("netsh int reset all");
    system("netsh int ipv4 reset");
    system("netsh int ipv6 reset");
    system("netsh winsock reset");
    system("netsh interface teredo set state disabled");
    system("netsh interface 6to4 set state disabled");
    system("netsh winsock reset");
    system("netsh int isatap set state disable");
    system("netsh int ip set global taskoffload=disabled");
    system("netsh int ip set global neighborcachelimit=4096");
    system("netsh int tcp set global timestamps=disabled");
    system("netsh int tcp set heuristics=disabled");
    system("netsh int tcp set global autotuninglevel=disable");
    system("netsh int tcp set global chimney=disabled");
    system("netsh int tcp set global ecncapability=disabled");
    system("netsh int tcp set global rss=enabled");
    system("netsh int tcp set global rsc=disabled");
    system("netsh int tcp set global dca=enabled");
    system("netsh int tcp set global netdma=enabled");
    system("netsh int tcp set global nonsackrttresiliency=disabled");
    system("netsh int tcp set security mpp=disabled");
    system("netsh int tcp set security profiles=disabled");
    system("netsh int ip set global icmpredirects=disabled");
    system("netsh int tcp set security mpp=disabled profiles=disabled");
    system("netsh int ip set global multicastforwarding=disabled");

    // internet optimization

    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"ForwardBroadcasts\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"IPEnableRouter\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"SyncDomainWithMembership\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"DefaultTTL\" /t REG_DWORD /d \"00000040\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnableICMPRedirect\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnablePMTUBHDetect\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnablePMTUDiscovery\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"MaxUserPort\" /t REG_DWORD /d \"0000fffe\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"Tcp1323Opts\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpTimedWaitDelay\" /t REG_DWORD /d \"0000001e\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"UseDomainNameDevolution\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"DeadGWDetectDefault\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"DontAddDefaultGatewayDefault\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TCPNoDelay\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpAckFrequency\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"SizReqBuf\" /t REG_DWORD /d \"00059819\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TCPInitalRtt\" /t REG_DWORD /d \"00049697\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpMaxDupAcks\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"MaxFreeTcbs\" /t REG_DWORD /d \"00065535\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"SackOpts\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpMaxDataRetransmissions\" /t REG_DWORD /d \"00000005\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnableDCA\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnableWsd\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"DisableTaskOffload\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpFinWait2Delay\" /t REG_DWORD /d \"0000018e\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"StrictTimeWaitSeqCheck\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpCreateAndConnectTcbRateLimitDepth\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TCPDelAckTicks\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v \"TcpAckFrequency\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v \"TCPNoDelay\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v \"IPAutoconfigurationEnabled\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v \"TCPDelAckTicks\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\" /v \"NonBestEffortLimit\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"Class\" /t REG_DWORD /d \"00000008\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"DnsPriority\" /t REG_DWORD /d \"00000006\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"HostsPriority\" /t REG_DWORD /d \"00000005\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"LocalPriority\" /t REG_DWORD /d \"00000004\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"NetbtPriority\" /t REG_DWORD /d \"00000007\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\" /v DODownloadMode /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections\" /v NC_ShowSharedAccessUI /t REG_DWORD /d \"0\" /f");

    // reg optimizations

    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\usbxhci\\Parameters\" /v \"ThreadPriority\" /t REG_DWORD /d \"0000001f\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBHUB3\\Parameters\" /v \"ThreadPriority\" /t REG_DWORD /d \"0000001f\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NDIS\\Parameters\" /v \"ThreadPriority\" /t REG_DWORD /d \"0000001f\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\Parameters\" /v \"ThreadPriority\" /t REG_DWORD /d \"0000001f\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettings\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettingsOverride\" /t REG_DWORD /d \"3\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettingsOverrideMask\" /t REG_DWORD /d \"3\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v \"EnableCfg\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettings\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettingsOverride\" /t REG_DWORD /d \"3\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettingsOverrideMask\" /t REG_DWORD /d \"3\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Memory Management\" /v \"EnableCfg\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet002\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettings\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet002\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettingsOverride\" /t REG_DWORD /d \"3\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet002\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettingsOverrideMask\" /t REG_DWORD /d \"3\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet002\\Control\\Session Manager\\Memory Management\" /v \"EnableCfg\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v \"DisableExceptionChainValidation\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v \"KernelSEHOPEnabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\kernel\" /v \"DisableExceptionChainValidation\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\kernel\" /v \"KernelSEHOPEnabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet002\\Control\\Session Manager\\kernel\" /v \"DisableExceptionChainValidation\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet002\\Control\\Session Manager\\kernel\" /v \"KernelSEHOPEnabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Scheduler\" /v \"EnablePreemption\" /t REG_DWORD /d \"-\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"JPEGImportQuality\" /t REG_DWORD /d \"00000100\" /f");
    system("reg.exe add \"HKCU\\Control Panel\\Desktop\" /v \"UserPreferencesMask\" /t REG_BINARY /d \"9032078010000000\" /f");
    system("reg.exe add \"HKCU\\Control Panel\\Desktop\\WindowMetrics\" /v \"MinAnimate\" REG_SZ /d 0 /f");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"TaskbarAnimations\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"IconsOnly\" /T REG_DWORD /d \"0\" /F");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ListviewAlphaSelect\" /T REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"DragFullWindows\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"FontSmoothing\" /t REG_SZ /d \"2\" /f");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /V \"ListviewShadow\" /T REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\DWM\" /V \"AlwaysHibernateThumbnails\" /T REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"Hidden\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowSuperHidden\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location\" /v \"Value\" /t REG_SZ /d \"Deny\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance\" /v fAllowToGetHelp /d \"0\" /t REG_DWORD /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\GameBar\" /v AutoGameModeEnabled /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKCU\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\\InprocServer32\" /f /ve");
    system("reg.exe add \"HKCU\\Software\\Classes\\CLSID\\{d93ed569-3b3e-4bff-8355-3c44f6a52bb5}\\InprocServer32\" /f /ve");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v \"DistributeTimers\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\DeviceGuard\" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v \"Max Cached Icons\" /t REG_SZ /d \"4096\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v \"SubscribedContent-338393Enabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v \"SubscribedContent-353694Enabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v \"SubscribedContent-353696Enabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowSyncProviderNotifications\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v \"DisableSoftLanding\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"AutoEndTasks\" /t REG_SZ /d \"1\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"HungAppTimeout\" /t REG_SZ /d \"2000\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"MenuShowDelay\" /t REG_SZ /d \"5\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"WaitToKillAppTimeout\" /t REG_SZ /d \"3000\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"LowLevelHooksTimeout\" /t REG_SZ /d \"2000\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"ActiveWndTrackTimeout\" /t REG_DWORD /d \"0000000a\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Mouse\" /v \"MouseHoverTime\" /t REG_SZ /d \"1\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Power\\PowerThrottling\" /v \"PowerThrottlingOff\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoLowDiskSpaceChecks\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"LinkResolveIgnoreLinkInfo\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoResolveSearch\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoResolveTrack\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoInternetOpenWith\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DesktopLivePreviewHoverTime\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"Start_ShowRun\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet002\\Control\" /v \"WaitToKillServiceTimeout\" /t REG_SZ /d \"2000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\" /v \"WaitToKillServiceTimeout\" /t REG_SZ /d \"2000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\" /v \"WaitToKillServiceTimeout\" /t REG_SZ /d \"2000\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"DisableThumbnails\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"FolderContentsInfoTip\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowEncryptCompressedColor\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /V ShowInfoTip /T REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowPreviewHandlers\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v \"EnableFirstLogonAnimation\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v \"EnableFirstLogonAnimation\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Device Metadata\" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection\" /v \"AllowTelemetry\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection\" /v AllowTelemetry /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\MRT\" /v DontOfferThroughWUAU /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows\" /v \"CEIPEnable\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\Software\\Microsoft\\SQMClient\\Windows\" /v CEIPEnable /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v \"AITEnable\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v \"DisableUAR\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v \"AllowTelemetry\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\AutoLogger\\AutoLogger-Diagtrack-Listener\" /v \"Start\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\AutoLogger\\SQMLogger\" /v \"Start\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v SmartScreenEnabled /t REG_SZ /d \"Off\" /f");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost\" /v \"SmartScreenEnabled\" /t \"REG_SZ\" /d \"Off\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance\" /v fAllowFullControl /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\" /v AppsUseLightTheme /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\" /v SystemUsesLightTheme /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v LaunchTo /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\" /v HwSchMode /t REG_DWORD /d \"2\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\" /v \"HiberbootEnabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /v \"LetAppsRunInBackground\" /t REG_DWORD /d \"2\" /f");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo\" /v Enabled /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\" /v \"NetworkThrottlingIndex\" /t REG_DWORD /d \"ffffffff\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Serialize\" /v \"Startupdelayinmsec\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\" /v \"SystemResponsiveness\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"Affinity\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"Background Only\" /t REG_SZ /d \"False\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"Clock Rate\" /t REG_DWORD /d \"00002710\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"GPU Priority\" /t REG_DWORD /d \"00000008\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"Priority\" /t REG_DWORD /d \"00000006\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"Scheduling Category\" /t REG_SZ /d \"High\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"SFIO Priority\" /t REG_SZ /d \"High\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\FTS\" /v \"EnableRID61684\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_FSEBehaviorMode\" /t REG_DWORD /d \"00000002\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_HonorUserFSEBehaviorMode\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_FSEBehavior\" /t REG_DWORD /d \"00000002\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_DXGIHonorFSEWindowsCompatible\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\default\\ApplicationManagement\\AllowGameDVR\" /v \"value\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_Enabled\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\PriorityControl\" /v \"Win32PrioritySeparation\" /t REG_DWORD /d \"00000038\" /f");
    system("reg.exe delete \"HKCU\\Control Panel\\Quick Actions\" /f");
    system("reg.exe delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /V \"LetAppsRunInBackground_UserInControlOfTheseApps\" /f");
    system("reg.exe delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /V \"LetAppsRunInBackground_ForceAllowTheseApps\" /f");
    system("reg.exe delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /V \"LetAppsRunInBackground_ForceDenyTheseApps\" /f");
    system("cls");
}

void optimization2() {
    system("mode 90,50");
    system("cls");

    // optimization usb

    system("powershell.exe -encodedCommand JABkAGUAdgBpAGMAZQBzAFUAUwBCACAAPQAgAEcAZQB0AC0AUABuAHAARABlAHYAaQBjAGUAIAB8ACAAdwBoAGUAcgBlACAAewAkAF8ALgBJAG4AcwB0AGEAbgBjAGUASQBkACAALQBsAGkAawBlACAAIgAqAFUAUwBCAFwAUgBPAE8AVAAqACIAfQAgACAAfAAgAA0ACgBGAG8AcgBFAGEAYwBoAC0ATwBiAGoAZQBjAHQAIAAtAFAAcgBvAGMAZQBzAHMAIAB7AA0ACgBHAGUAdAAtAEMAaQBtAEkAbgBzAHQAYQBuAGMAZQAgAC0AQwBsAGEAcwBzAE4AYQBtAGUAIABNAFMAUABvAHcAZQByAF8ARABlAHYAaQBjAGUARQBuAGEAYgBsAGUAIAAtAE4AYQBtAGUAcwBwAGEAYwBlACAAcgBvAG8AdABcAHcAbQBpACAADQAKAH0ADQAKAA0ACgBmAG8AcgBlAGEAYwBoACAAKAAgACQAZABlAHYAaQBjAGUAIABpAG4AIAAkAGQAZQB2AGkAYwBlAHMAVQBTAEIAIAApAA0ACgB7AA0ACgAgACAAIAAgAFMAZQB0AC0AQwBpAG0ASQBuAHMAdABhAG4AYwBlACAALQBOAGEAbQBlAHMAcABhAGMAZQAgAHIAbwBvAHQAXAB3AG0AaQAgAC0AUQB1AGUAcgB5ACAAIgBTAEUATABFAEMAVAAgACoAIABGAFIATwBNACAATQBTAFAAbwB3AGUAcgBfAEQAZQB2AGkAYwBlAEUAbgBhAGIAbABlACAAVwBIAEUAUgBFACAASQBuAHMAdABhAG4AYwBlAE4AYQBtAGUAIABMAEkASwBFACAAJwAlACQAKAAkAGQAZQB2AGkAYwBlAC4AUABOAFAARABlAHYAaQBjAGUASQBEACkAJQAnACIAIAAtAFAAcgBvAHAAZQByAHQAeQAgAEAAewBFAG4AYQBiAGwAZQA9ACQARgBhAGwAcwBlAH0AIAAtAFAAYQBzAHMAVABoAHIAdQANAAoAfQANAAoADQAKACQAYQBkAGEAcAB0AGUAcgBzACAAPQAgAEcAZQB0AC0ATgBlAHQAQQBkAGEAcAB0AGUAcgAgAC0AUABoAHkAcwBpAGMAYQBsACAAfAAgAEcAZQB0AC0ATgBlAHQAQQBkAGEAcAB0AGUAcgBQAG8AdwBlAHIATQBhAG4AYQBnAGUAbQBlAG4AdAANAAoAIAAgACAAIABmAG8AcgBlAGEAYwBoACAAKAAkAGEAZABhAHAAdABlAHIAIABpAG4AIAAkAGEAZABhAHAAdABlAHIAcwApAA0ACgAgACAAIAAgACAAIAAgACAAewANAAoAIAAgACAAIAAgACAAIAAgACQAYQBkAGEAcAB0AGUAcgAuAEEAbABsAG8AdwBDAG8AbQBwAHUAdABlAHIAVABvAFQAdQByAG4ATwBmAGYARABlAHYAaQBjAGUAIAA9ACAAJwBEAGkAcwBhAGIAbABlAGQAJwANAAoAIAAgACAAIAAgACAAIAAgACQAYQBkAGEAcAB0AGUAcgAgAHwAIABTAGUAdAAtAE4AZQB0AEEAZABhAHAAdABlAHIAUABvAHcAZQByAE0AYQBuAGEAZwBlAG0AZQBuAHQADQAKACAAIAAgACAAIAAgACAAIAB9AA==");

    // optimization power config

    system("powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61");
    system("powercfg -h off");
    system("powercfg.exe -change -monitor-timeout-dc 0");
    system("powercfg.exe -change -standby-timeout-dc 0");
    system("powercfg.exe -change -hibernate-timeout-dc 0");
    system("powercfg.exe -change -monitor-timeout-ac 0");
    system("powercfg.exe -change -standby-timeout-ac 0");
    system("powercfg.exe -change -hibernate-timeout-ac 0");
    system("powercfg -SETDCVALUEINDEX SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 0");
    system("powercfg -SETACVALUEINDEX SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 0");
    system("powercfg -SETACVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0");
    system("powercfg -SETDCVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 3");
    system("powercfg -SETACVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3");
    system("powercfg -SETDCVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3");
    system("powercfg -SETDCVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0");
    system("powercfg -SETACVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0");
    system("bcdedit /set tscsyncpolicy Enhanced");
    system("bcdedit /deletevalue useplatformclock");
    system("bcdedit /set disabledynamictick yes");
    system("powershell Disable-NetAdapterLso -Name \"*\"");
    system("powershell \"ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}\"");
    system("powershell \"ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}\"");
    system("cls");

    // internet optimization

    system("ipconfig /flushdns");
    system("netsh int reset all");
    system("netsh int ipv4 reset");
    system("netsh int ipv6 reset");
    system("netsh winsock reset");
    system("netsh interface teredo set state disabled");
    system("netsh interface 6to4 set state disabled");
    system("netsh winsock reset");
    system("netsh int isatap set state disable");
    system("netsh int ip set global taskoffload=disabled");
    system("netsh int ip set global neighborcachelimit=4096");
    system("netsh int tcp set global timestamps=disabled");
    system("netsh int tcp set heuristics=disabled");
    system("netsh int tcp set global autotuninglevel=disable");
    system("netsh int tcp set global chimney=disabled");
    system("netsh int tcp set global ecncapability=disabled");
    system("netsh int tcp set global rss=enabled");
    system("netsh int tcp set global rsc=disabled");
    system("netsh int tcp set global dca=enabled");
    system("netsh int tcp set global netdma=enabled");
    system("netsh int tcp set global nonsackrttresiliency=disabled");
    system("netsh int tcp set security mpp=disabled");
    system("netsh int tcp set security profiles=disabled");
    system("netsh int ip set global icmpredirects=disabled");
    system("netsh int tcp set security mpp=disabled profiles=disabled");
    system("netsh int ip set global multicastforwarding=disabled");

    // internet optimization

    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"ForwardBroadcasts\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"IPEnableRouter\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"SyncDomainWithMembership\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"DefaultTTL\" /t REG_DWORD /d \"00000040\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnableICMPRedirect\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnablePMTUBHDetect\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnablePMTUDiscovery\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"MaxUserPort\" /t REG_DWORD /d \"0000fffe\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"Tcp1323Opts\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpTimedWaitDelay\" /t REG_DWORD /d \"0000001e\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"UseDomainNameDevolution\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"DeadGWDetectDefault\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"DontAddDefaultGatewayDefault\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TCPNoDelay\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpAckFrequency\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"SizReqBuf\" /t REG_DWORD /d \"00059819\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TCPInitalRtt\" /t REG_DWORD /d \"00049697\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpMaxDupAcks\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"MaxFreeTcbs\" /t REG_DWORD /d \"00065535\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"SackOpts\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpMaxDataRetransmissions\" /t REG_DWORD /d \"00000005\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnableDCA\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnableWsd\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"DisableTaskOffload\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpFinWait2Delay\" /t REG_DWORD /d \"0000018e\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"StrictTimeWaitSeqCheck\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpCreateAndConnectTcbRateLimitDepth\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TCPDelAckTicks\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v \"TcpAckFrequency\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v \"TCPNoDelay\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v \"IPAutoconfigurationEnabled\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v \"TCPDelAckTicks\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\" /v \"NonBestEffortLimit\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"Class\" /t REG_DWORD /d \"00000008\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"DnsPriority\" /t REG_DWORD /d \"00000006\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"HostsPriority\" /t REG_DWORD /d \"00000005\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"LocalPriority\" /t REG_DWORD /d \"00000004\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"NetbtPriority\" /t REG_DWORD /d \"00000007\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\" /v DODownloadMode /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections\" /v NC_ShowSharedAccessUI /t REG_DWORD /d \"0\" /f");

    // reg optimizations

    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\usbxhci\\Parameters\" /v \"ThreadPriority\" /t REG_DWORD /d \"0000001f\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBHUB3\\Parameters\" /v \"ThreadPriority\" /t REG_DWORD /d \"0000001f\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NDIS\\Parameters\" /v \"ThreadPriority\" /t REG_DWORD /d \"0000001f\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\Parameters\" /v \"ThreadPriority\" /t REG_DWORD /d \"0000001f\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettings\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettingsOverride\" /t REG_DWORD /d \"3\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettingsOverrideMask\" /t REG_DWORD /d \"3\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v \"EnableCfg\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettings\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettingsOverride\" /t REG_DWORD /d \"3\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettingsOverrideMask\" /t REG_DWORD /d \"3\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Memory Management\" /v \"EnableCfg\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet002\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettings\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet002\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettingsOverride\" /t REG_DWORD /d \"3\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet002\\Control\\Session Manager\\Memory Management\" /v \"FeatureSettingsOverrideMask\" /t REG_DWORD /d \"3\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet002\\Control\\Session Manager\\Memory Management\" /v \"EnableCfg\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v \"DisableExceptionChainValidation\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v \"KernelSEHOPEnabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\kernel\" /v \"DisableExceptionChainValidation\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\kernel\" /v \"KernelSEHOPEnabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet002\\Control\\Session Manager\\kernel\" /v \"DisableExceptionChainValidation\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\ControlSet002\\Control\\Session Manager\\kernel\" /v \"KernelSEHOPEnabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Scheduler\" /v \"EnablePreemption\" /t REG_DWORD /d \"-\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"JPEGImportQuality\" /t REG_DWORD /d \"00000100\" /f");
    system("reg.exe add \"HKCU\\Control Panel\\Desktop\" /v \"UserPreferencesMask\" /t REG_BINARY /d \"9032078010000000\" /f");
    system("reg.exe add \"HKCU\\Control Panel\\Desktop\\WindowMetrics\" /v \"MinAnimate\" REG_SZ /d 0 /f");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"TaskbarAnimations\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"IconsOnly\" /T REG_DWORD /d \"0\" /F");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ListviewAlphaSelect\" /T REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"DragFullWindows\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"FontSmoothing\" /t REG_SZ /d \"2\" /f");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /V \"ListviewShadow\" /T REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\DWM\" /V \"AlwaysHibernateThumbnails\" /T REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"Hidden\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowSuperHidden\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location\" /v \"Value\" /t REG_SZ /d \"Deny\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance\" /v fAllowToGetHelp /d \"0\" /t REG_DWORD /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\GameBar\" /v AutoGameModeEnabled /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKCU\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\\InprocServer32\" /f /ve");
    system("reg.exe add \"HKCU\\Software\\Classes\\CLSID\\{d93ed569-3b3e-4bff-8355-3c44f6a52bb5}\\InprocServer32\" /f /ve");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v \"DistributeTimers\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\DeviceGuard\" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v \"Max Cached Icons\" /t REG_SZ /d \"4096\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v \"SubscribedContent-338393Enabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v \"SubscribedContent-353694Enabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v \"SubscribedContent-353696Enabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowSyncProviderNotifications\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v \"DisableSoftLanding\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"AutoEndTasks\" /t REG_SZ /d \"1\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"HungAppTimeout\" /t REG_SZ /d \"2000\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"MenuShowDelay\" /t REG_SZ /d \"5\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"WaitToKillAppTimeout\" /t REG_SZ /d \"3000\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"LowLevelHooksTimeout\" /t REG_SZ /d \"2000\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Desktop\" /v \"ActiveWndTrackTimeout\" /t REG_DWORD /d \"0000000a\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Control Panel\\Mouse\" /v \"MouseHoverTime\" /t REG_SZ /d \"1\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Power\\PowerThrottling\" /v \"PowerThrottlingOff\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoLowDiskSpaceChecks\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"LinkResolveIgnoreLinkInfo\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoResolveSearch\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoResolveTrack\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoInternetOpenWith\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DesktopLivePreviewHoverTime\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"Start_ShowRun\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet002\\Control\" /v \"WaitToKillServiceTimeout\" /t REG_SZ /d \"2000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\" /v \"WaitToKillServiceTimeout\" /t REG_SZ /d \"2000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\" /v \"WaitToKillServiceTimeout\" /t REG_SZ /d \"2000\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"DisableThumbnails\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"FolderContentsInfoTip\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowEncryptCompressedColor\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /V ShowInfoTip /T REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowPreviewHandlers\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v \"EnableFirstLogonAnimation\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v \"EnableFirstLogonAnimation\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Device Metadata\" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection\" /v \"AllowTelemetry\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection\" /v AllowTelemetry /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\MRT\" /v DontOfferThroughWUAU /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows\" /v \"CEIPEnable\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\Software\\Microsoft\\SQMClient\\Windows\" /v CEIPEnable /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v \"AITEnable\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v \"DisableUAR\" /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v \"AllowTelemetry\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\AutoLogger\\AutoLogger-Diagtrack-Listener\" /v \"Start\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\AutoLogger\\SQMLogger\" /v \"Start\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v SmartScreenEnabled /t REG_SZ /d \"Off\" /f");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost\" /v \"SmartScreenEnabled\" /t \"REG_SZ\" /d \"Off\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance\" /v fAllowFullControl /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\" /v AppsUseLightTheme /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\" /v SystemUsesLightTheme /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v LaunchTo /t REG_DWORD /d \"1\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\" /v HwSchMode /t REG_DWORD /d \"2\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\" /v \"HiberbootEnabled\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /v \"LetAppsRunInBackground\" /t REG_DWORD /d \"2\" /f");
    system("reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo\" /v Enabled /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\" /v \"NetworkThrottlingIndex\" /t REG_DWORD /d \"ffffffff\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Serialize\" /v \"Startupdelayinmsec\" /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\" /v \"SystemResponsiveness\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"Affinity\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"Background Only\" /t REG_SZ /d \"False\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"Clock Rate\" /t REG_DWORD /d \"00002710\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"GPU Priority\" /t REG_DWORD /d \"00000008\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"Priority\" /t REG_DWORD /d \"00000006\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"Scheduling Category\" /t REG_SZ /d \"High\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"SFIO Priority\" /t REG_SZ /d \"High\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\nvlddmkm\\FTS\" /v \"EnableRID61684\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_FSEBehaviorMode\" /t REG_DWORD /d \"00000002\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_HonorUserFSEBehaviorMode\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_FSEBehavior\" /t REG_DWORD /d \"00000002\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_DXGIHonorFSEWindowsCompatible\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\default\\ApplicationManagement\\AllowGameDVR\" /v \"value\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_Enabled\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\PriorityControl\" /v \"Win32PrioritySeparation\" /t REG_DWORD /d \"00000038\" /f");
    system("reg.exe delete \"HKCU\\Control Panel\\Quick Actions\" /f");
    system("reg.exe delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /V \"LetAppsRunInBackground_UserInControlOfTheseApps\" /f");
    system("reg.exe delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /V \"LetAppsRunInBackground_ForceAllowTheseApps\" /f");
    system("reg.exe delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /V \"LetAppsRunInBackground_ForceDenyTheseApps\" /f");
    system("cls");
}

void optimization3() {
    system("mode 90,50");
    system("cls");

    // internet optimization

    system("ipconfig /flushdns");
    system("netsh int reset all");
    system("netsh int ipv4 reset");
    system("netsh int ipv6 reset");
    system("netsh winsock reset");
    system("netsh interface teredo set state disabled");
    system("netsh interface 6to4 set state disabled");
    system("netsh winsock reset");
    system("netsh int isatap set state disable");
    system("netsh int ip set global taskoffload=disabled");
    system("netsh int ip set global neighborcachelimit=4096");
    system("netsh int tcp set global timestamps=disabled");
    system("netsh int tcp set heuristics=disabled");
    system("netsh int tcp set global autotuninglevel=disable");
    system("netsh int tcp set global chimney=disabled");
    system("netsh int tcp set global ecncapability=disabled");
    system("netsh int tcp set global rss=enabled");
    system("netsh int tcp set global rsc=disabled");
    system("netsh int tcp set global dca=enabled");
    system("netsh int tcp set global netdma=enabled");
    system("netsh int tcp set global nonsackrttresiliency=disabled");
    system("netsh int tcp set security mpp=disabled");
    system("netsh int tcp set security profiles=disabled");
    system("netsh int ip set global icmpredirects=disabled");
    system("netsh int tcp set security mpp=disabled profiles=disabled");
    system("netsh int ip set global multicastforwarding=disabled");

    // internet optimization

    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"ForwardBroadcasts\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"IPEnableRouter\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"SyncDomainWithMembership\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"DefaultTTL\" /t REG_DWORD /d \"00000040\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnableICMPRedirect\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnablePMTUBHDetect\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnablePMTUDiscovery\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"MaxUserPort\" /t REG_DWORD /d \"0000fffe\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"Tcp1323Opts\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpTimedWaitDelay\" /t REG_DWORD /d \"0000001e\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"UseDomainNameDevolution\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"DeadGWDetectDefault\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"DontAddDefaultGatewayDefault\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TCPNoDelay\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpAckFrequency\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"SizReqBuf\" /t REG_DWORD /d \"00059819\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TCPInitalRtt\" /t REG_DWORD /d \"00049697\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpMaxDupAcks\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"MaxFreeTcbs\" /t REG_DWORD /d \"00065535\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"SackOpts\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpMaxDataRetransmissions\" /t REG_DWORD /d \"00000005\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnableDCA\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"EnableWsd\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"DisableTaskOffload\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpFinWait2Delay\" /t REG_DWORD /d \"0000018e\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"StrictTimeWaitSeqCheck\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TcpCreateAndConnectTcbRateLimitDepth\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v \"TCPDelAckTicks\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v \"TcpAckFrequency\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v \"TCPNoDelay\" /t REG_DWORD /d \"00000001\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v \"IPAutoconfigurationEnabled\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\" /v \"TCPDelAckTicks\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\" /v \"NonBestEffortLimit\" /t REG_DWORD /d \"00000000\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"Class\" /t REG_DWORD /d \"00000008\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"DnsPriority\" /t REG_DWORD /d \"00000006\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"HostsPriority\" /t REG_DWORD /d \"00000005\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"LocalPriority\" /t REG_DWORD /d \"00000004\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\ServiceProvider\" /v \"NetbtPriority\" /t REG_DWORD /d \"00000007\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\" /v DODownloadMode /t REG_DWORD /d \"0\" /f");
    system("reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections\" /v NC_ShowSharedAccessUI /t REG_DWORD /d \"0\" /f");
    system("cls");

}

void optimization4() {
    system("mode 90,50");
    system("cls");

    system("del /s /f /q \"%localappdata%\\Microsoft\\Windows\\Temporary Internet Files\\*.*\"");
    system("rd /s /q \"%localappdata%\\Microsoft\\Windows\\Temporary Internet Files\"");
    system("md \"%localappdata%\\Microsoft\\Windows\\Temporary Internet Files\"");
    system("del /s /f /q \"%userprofile%\\AppData\\Local\\Temp\\*.*\"");
    system("rd /s /q \"%userprofile%\\AppData\\Local\\Temp\"");
    system("md \"%userprofile%\\AppData\\Local\\Temp\"");
    system("del /s /f /q \"%windir%\\Temp\\*.*\"");
    system("rd /s /q \"%windir%\\Temp\"");
    system("md \"%windir%\\Temp\"");
    system("del /s /f /q \"%systemroot%\\SoftwareDistribution\\Download\\*.*\"");
    system("del /s /f /q \"%userprofile%\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.*\"");
    system("rd /s /q \"%userprofile%\\AppData\\Local\\Microsoft\\Windows\\Explorer\\ThumbnailCache\"");
    system("md \"%userprofile%\\AppData\\Local\\Microsoft\\Windows\\Explorer\\ThumbnailCache\"");
    system("del /s /f /q \"%windir%\\System32\\config\\systemprofile\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\*.*\"");
    system("del /s /f /q \"%userprofile%\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\*.*\"");
    system("rd /s /q \"%userprofile%\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\"");
    system("md \"%userprofile%\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\"");
    system("del /s /f /q \"%userprofile%\\AppData\\Local\\Microsoft\\Windows\\Explorer\\iconcache*.*\"");
    system("del /s /f /q \"%windir%\\Prefetch\\*.*\"");
    system("del /s /f /q \"%windir%\\SoftwareDistribution\\Download\\*.*\"");
    system("del /s /f /q \"C:\\Users\\*\\AppData\\Local\\Temp\\*.*\"");
    system("rd /s /q \"C:\\Users\\*\\AppData\\Local\\Temp\"");
    system("md \"C:\\Users\\*\\AppData\\Local\\Temp\"");
    system("del /s /f /q \"%userprofile%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\*.*\"");
    system("del /s /f /q \"%userprofile%\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_*\\AC\\INetCache\\*.*\"");
    system("del /s /f /q \"%userprofile%\\AppData\\Local\\Programs\\*\\Cache\\*.*\"");
    
    system("cls");
}

// installations 

void memoryCleaner() {
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://www.mediafire.com/file/mooc2t1mra9utw2/Memory_Cleaner.rar/file");
    std::cout << "'extract here' .rar archive and execute a Memory Cleaner.exe!";
    system("timeout /t -1");
}

void discord() {
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://www.mediafire.com/file/4fd1yqk3uuzpx2b/DiscordSetup.exe/file");
    std::cout << "execute DiscordSetup.exe!";
    system("timeout /t -1");
}

void steam() {
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe");
    std::cout << "execute SteamSetup.exe!";
    system("timeout /t -1");
}

void github() {
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://www.mediafire.com/file/wbouqd0gx0bt10l/GitHubDesktopSetup-x64.exe/file");
    std::cout << "execute GitHubDesktopSetup.exe!";
    system("timeout /t -1");
}

void visualC() {
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://download1519.mediafire.com/mnqczktpja0g/vq2xp24j34w4034/All+Visual+Studio+%28Extract+Here%29.rar");
    std::cout << "'extract here' .rar archive and execute a Installer.bat!";
    system("timeout /t -1");
}

void nvCleanInstall() {
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://www.mediafire.com/file/jyfxt1zg56h90mx/NVCleanstall_1.13.0_new_version.exe/file");
    std::cout << "execute NVCleanInstall.exe!";
    system("timeout /t -1");
}

void nvidiaProfileInspector() {
    system("cls");
    system("color a");

    system("start https://www.mediafire.com/file/i11jhuf3026u9vz/nvdiaProfileInspector.rar/file");
    std::cout << "'extract here' .rar archive and execute a nvdiaProfileInspector.exe!";
    system("timeout /t -1");
}

void hwMonitor() {
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://www.mediafire.com/file/zthh0sicsw04q3s/hwmonitor.exe/file");
    std::cout << "execute hwmonitor.exe!";
    system("timeout /t -1");
}

void gpuZ() {
    system("cls");
    system("color a");

    system("start https://www.mediafire.com/file/no9iteyx9x6oshl/gpu-z.exe/file");
    std::cout << "execute gpu-z.exe!";
    system("timeout /t -1");
}

void ccleaner() {
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://www.mediafire.com/file/5dcwznxro048d5h/ccleaner.exe/file");
    std::cout << "execute ccleaner.exe!";
    system("timeout /t -1");
}

void quickCpu() {
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://www.mediafire.com/file/0axqeixxayvb199/QuickCpuSetup-x64.msi/file");
    std::cout << "execute QuickCpuSetup-x64.exe!";
    system("timeout /t -1");
}

void spotify() {
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://www.mediafire.com/file/5u1aix6j3b7ypue/SpotifySetup.exe/file");
    std::cout << "execute SpotifySetup.exe!";
    system("timeout /t -1");
}

void photoshop() {
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://www.mediafire.com/file/hd54smqyr90oavo/Adobe_Photoshop_2022_v23.4.2.603.rar/file");
    std::cout << "'extract here' .rar archive and execute setup!";
    system("timeout /t -1");
}

// compressors

void zip() {
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://www.mediafire.com/file/ssflgqmdwpx8yfw/7zip-x64.exe/file");
    std::cout << "execute installer...\n";
    system("timeout /t -1");
}

void rar(){
    system("cls");
    system("color a");
    system("mode 90, 13");

    system("start https://www.mediafire.com/file/2inm2goplp2an2n/winrar-x64.exe/file");
    std::cout << "execute installer...\n";
    system("timeout /t -1");
}

// browsers

void chrome(){
    system("cls");
    system("color a");
    system("mode 90,13");

    system("start https://www.mediafire.com/file/nggx6701qn5c96p/ChromeSetup.exe/file");
    std::cout << "execute ChromeSetup.exe!\n";
    system("timeout /t -1");
}

void operaGX(){
    system("cls");
    system("color a");
    system("mode 90,13");

    system("start https://www.mediafire.com/file/tofy2eh7cp2y6ji/OperaGXSetup.exe/file");
    std::cout << "execute ChromeSetup.exe!\n";
    system("timeout /t -1");
}

void brave(){
    system("cls");
    system("color a");
    system("mode 90,13");

    system("start https://www.mediafire.com/file/28ckxo74ld9yarl/BraveBrowserSetup-CGE651.exe/file");
    std::cout << "execute ChromeSetup.exe!\n";
    system("timeout /t -1");
}

void firefox(){
    system("cls");
    system("color a");
    system("mode 90,13");

    system("start https://www.mediafire.com/file/crt7nek7dt8ygrm/FirefoxSetup.exe/file");
    std::cout << "execute ChromeSetup.exe!\n";
    system("timeout /t -1");
}

// fps packs

void minecraft() {
    system("cls");
    system("color a");
    system("mode 90,13");

    system("start https://www.mediafire.com/file/ixnoioi6hp90wyb/Minecraft_pack.rar/file");
    std::cout << "recommended: in-game settings and jvm arguments!\n";
    system("timeout /t -1");
}

void valorant() {
    system("cls");
    system("color a");
    system("mode 90,13");

    system("start https://www.mediafire.com/file/6qfhoj8h18yxp93/Valorant_pack.rar/file");
    std::cout << "recommended: only in-game settings and .reg files\n";
    system("timeout /t -1");
}

void fortnite() {
    system("cls");
    system("color a");
    system("mode 90,13");

    system("start https://www.mediafire.com/file/6vc413ykvnoazuw/Fornite_pack.rar/file");
    std::cout << "recommended: only in-game settings and .reg files\n";
    system("timeout /t -1");
}

void csgo() {
    system("cls");
    system("color a");
    system("mode 90,13");

    system("start https://www.mediafire.com/file/lbaqum725t0xjey/Csgo_pack.rar/file");
    std::cout << "recommended: only in-game settings and .reg 'high' priority\n";
    system("timeout /t -1");
}

void pubg() {
    system("cls");
    system("color a");
    system("mode 90,13");

    system("start https://www.mediafire.com/file/zt0ssjrc1s93dk1/Pubg_pack.rar/file");
    std::cout << "recommended: only in-game settings\n";
    system("timeout /t -1");
}

int main() {
    system("title Tweaker w10");

    authenticator();

    char choice;
    while (true) {
        mainMenu();
        std::cout << "Select: ";
        std::cin >> choice;

        if (choice == '1') {
            system("cls");
            std::cout << "loading...\n";
            system("timeout /t  2");
            system("cls");
            optimization1(); // optimize all system
        } else if (choice == '2') {
            system("cls");
            std::cout << "loading...\n";
            system("timeout /t  2");
            system("cls");
            optimization2(); // optimize all system (services will not be disabled)
        } else if (choice == '3') {
            system("cls");
            std::cout << "loading...\n";
            system("timeout /t  2");
            system("cls");
            optimization3(); // optimize internet
        } else if (choice == '4') {
            system("cls");
            std::cout << "loading...\n";
            system("timeout /t  2");
            system("cls");
            optimization4(); // clean up
        } else if (choice == '5') {
            char choiceInstall;
            int x = 0, x2, x3, x4, x5;
            while (x == 0) {
                system("cls");
                std::cout << "loading...\n";
                system("timeout /t  1");
                system("cls");
                downloadMenu(); // download apps
                std::cout << "Select: ";
                std::cin >> choiceInstall;

                switch (choiceInstall) {
                    case '1':
                        system("cls");
                        std::cout << "loading...\n";
                        system("timeout /t  1");
                        system("cls");
                        memoryCleaner();
                        break;

                    case '2':
                        system("cls");
                        std::cout << "loading...\n";
                        system("timeout /t  1");
                        system("cls");
                        discord();
                        break;

                    case '3':
                        system("cls");
                        std::cout << "loading...\n";
                        system("timeout /t  1");
                        system("cls");
                        steam();
                        break;

                    case '4':
                        system("cls");
                        std::cout << "loading...\n";
                        system("timeout /t  1");
                        system("cls");
                        github();
                        break;

                    case '5':
                        x2 = 0;
                        char choiceBrowser;
                        while (x2 == 0) {
                            system("cls");
                            std::cout << "loading...\n";
                            system("timeout /t  1");
                            system("cls");
                            menuBrowsers(); // choice browsers chrome / opera / brave / firefox
                            std::cout << "Select: ";
                            std::cin >> choiceBrowser;
                            
                            switch (choiceBrowser) {
                                case '1':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    chrome();
                                    break;

                                case '2':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    operaGX();
                                    break;

                                case '3':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    brave();
                                    break;

                                case '4':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    firefox();
                                    break;

                                case 'x':
                                case 'X':
                                    x2 = 1;
                                    break;

                                default:
                                    std::cerr << "Invalid choice. Please select again.\n";
                                    break;
                                }
                            }
                        break;

                    case '6':
                        x3 = 0;
                        char choiceRar;
                        while (x3 == 0) {
                            system("cls");
                            std::cout << "loading...\n";
                            system("timeout /t  1");
                            system("cls");
                            menuRar(); // choice 7zip/rar
                            std::cout << "Select: ";
                            std::cin >> choiceRar;

                            switch (choiceRar) {
                                case '1':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    zip();
                                    break;

                                case '2':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    rar();
                                    break;

                                case 'x':
                                case 'X':
                                    x3 = 1;
                                    break;

                                default:
                                    std::cerr << "Invalid choice. Please select again.\n";
                                    break;
                                }
                            }
                        break;

                    case '7':
                        system("cls");
                        std::cout << "loading...\n";
                        system("timeout /t  1");
                        system("cls");
                        visualC();
                        break;

                    case '8':
                        x4 = 0;
                        char moreOptions;
                        while (x4 == 0) {
                            system("cls");
                            std::cout << "loading...\n";
                            system("timeout /t  1");
                            system("cls");
                            optionsMenu();
                            std::cout << "Select: ";
                            std::cin >> moreOptions;

                            switch (moreOptions) {
                                case '1':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    nvCleanInstall();
                                    break;

                                case '2':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    nvidiaProfileInspector();
                                    break;

                                case '3':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    hwMonitor();
                                    break;

                                case '4':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    gpuZ();
                                    break;

                                case '5':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    ccleaner();
                                    break;

                                case '6':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    quickCpu();
                                    break;

                                case '7':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");      
                                    spotify();
                                    break;

                                case '8':
                                    system("cls");
                                    std::cout << "loading...\n";
                                    system("timeout /t  1");
                                    system("cls");
                                    photoshop();
                                    break;

                                case '9':
                                    x5 = 0;
                                    char fpspack;
                                    while(x5 == 0) {
                                        system("cls");
                                        std::cout << "loading...\n";
                                        system("timeout /t  1");
                                        system("cls");
                                        fpsPacks();
                                        std::cout << "Select: ";
                                        std::cin >> fpspack;

                                        switch(fpspack) {
                                            case '1':
                                            system("cls");
                                            std::cout << "loading...\n";
                                            system("timeout /t  1");
                                            system("cls");
                                            minecraft();
                                            break;

                                            case '2':
                                            system("cls");
                                            std::cout << "loading...\n";
                                            system("timeout /t  1");
                                            system("cls");
                                            valorant();
                                            break;

                                            case '3':
                                            system("cls");
                                            std::cout << "loading...\n";
                                            system("timeout /t  1");
                                            system("cls");
                                            fortnite();
                                            break;

                                            case '4':
                                            system("cls");
                                            std::cout << "loading...\n";
                                            system("timeout /t  1");
                                            system("cls");
                                            csgo();
                                            break;

                                            case '5':
                                            system("cls");
                                            std::cout << "loading...\n";
                                            system("timeout /t  1");
                                            system("cls");
                                            pubg();
                                            break;

                                            case 'x':
                                            case 'X':
                                                x5 = 1;
                                                break;

                                            default:
                                                std::cerr << "invalid choice. Please select again.\n";
                                                break;
                                            }
                                        }
                                    break;

                                case 'x':
                                case 'X':
                                    x4 = 1;
                                    break;
                                
                                default:
                                    std::cerr << "invalid choice. Please select again.\n";
                                    break;

                                }
                            }
                        break;

                    case 'x':
                    case 'X':
                        system("cls");
                        std::cout << "loading...\n";
                        system("timeout /t  1");
                        system("cls");
                        x = 1;
                        break;

                    default:
                        std::cerr << "invalid choice. Please select again.\n";
                        break;
                    }
                }
            } else if (choice == 'x') {
                system("cls");
                std::cout << "thanks for using :)\n";
                return 0;
            } else if (choice == 'X') {
                system("cls");
                std::cout << "thanks for using :)\n";
                return 0;
            } else {
                system("cls");
                system("color 4");
                std::cerr << "invalid choice. Please select again.\n";
                system("timeout /t 2");
            }
        }
    return 0;
}