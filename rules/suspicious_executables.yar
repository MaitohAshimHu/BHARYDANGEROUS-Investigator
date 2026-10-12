rule Suspicious_Process_Hollowing : malware high
{
    meta:
        description = "Detects API calls indicative of process hollowing or injection"
        author = "Ashim"
        severity = "HIGH"
    strings:
        $a1 = "VirtualAllocEx"
        $a2 = "WriteProcessMemory"
        $a3 = "CreateRemoteThread"
        $a4 = "SetThreadContext"
        $a5 = "NtUnmapViewOfSection"
    condition:
        all of ($a1, $a2, $a3) or all of ($a1, $a2, $a4)
}
