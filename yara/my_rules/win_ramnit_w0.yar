rule win_ramnit_w0 {
    meta:
        author = "@VK_Intel"
        description = "Detects Ramnit banking malware VNC module"
        reference = "http://www.vkremez.com/2018/02/deeper-dive-into-ramnit-banker-vnc-ifsb.html"
        hash = "888b2c614567fb5b4474ddeeb453f8cd9f44d72efb325f7e3652fd0f748c08f1"
        malpedia_version = "20180226"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s0 = "Failed mapping a section to the target process, status 0x%x" fullword ascii
        $s1 = "Unable to map the section into the target process, error %u" fullword ascii
        $s2 = "Unable to resolve target process import, error %u" fullword ascii
        $s3 = "No module found for the target process (%u) architecture" fullword ascii
        $s4 = "A section of %u bytes mapped to the target process at 0x%p" fullword ascii
        $s5 = "CreateProcessAsUserA %s->%s failed" fullword ascii
        $s6 = "Dep PsSupGetProcessModules, ModCount = %d " fullword ascii
        $s7 = "ActiveDll: PatchProcessMemory failed, error: %u" fullword ascii
        $s8 = "CreateProcessAsUserW %S->%S failed" fullword ascii
        $s9 = "AcInjectDll: GetOEP failed, error: %u" fullword ascii
        $s10 = "Shared section mapped at 0x%p. Starting within VNC session process." fullword ascii
        $s11 = "CreateToolhelp32Snapshot (of processes) failed err=%lu" fullword ascii
    condition:
        all of them
}
