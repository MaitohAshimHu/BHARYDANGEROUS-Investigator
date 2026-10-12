rule Ransomware_Note_Common : ransomware high
{
    meta:
        description = "Detects common ransomware payment notices and instructions"
        author = "Ashim"
        severity = "HIGH"
    strings:
        $r1 = "YOUR FILES ARE ENCRYPTED"
        $r2 = "All your important files have been encrypted"
        $r3 = "send bitcoin to this address"
        $r4 = "Tor Browser to communicate with us"
        $r5 = "vssadmin.exe Delete Shadows /All /Quiet"
    condition:
        any of them
}
