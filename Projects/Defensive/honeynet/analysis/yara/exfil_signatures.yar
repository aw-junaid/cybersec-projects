rule HighEntropyFile {
    meta:
        description = "Detects high entropy files (likely encrypted/compressed)"
        author = "Honeynet Team"
    condition:
        filesize < 100MB and
        entropy > 7.0
}

rule PE_File {
    meta:
        description = "Detects Windows PE files"
        author = "Honeynet Team"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}

rule Shellcode {
    meta:
        description = "Detects common shellcode patterns"
        author = "Honeynet Team"
    strings:
        $xor = { 31 C? [0-4] 31 D? [0-4] 31 F? }  // XOR patterns
        $int80 = { CD 80 }  // Linux int 0x80
        $int21 = { CD 21 }  // DOS int 0x21
    condition:
        any of them
}

rule Script_Dropper {
    meta:
        description = "Detects script-based droppers"
        author = "Honeynet Team"
    strings:
        $powershell = "powershell" nocase
        $cmd = "cmd.exe" nocase
        $base64 = /[A-Za-z0-9+\/]{40,}={0,2}/
    condition:
        any of ($powershell, $cmd) and $base64
}
