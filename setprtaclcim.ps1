<#
.SYNOPSIS
Set full access control for Authenticated Users to all printers.
.NOTES
Set printer acl by cim ver 1.00

MIT License

Copyright (c) 2024 Isao Sato

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>

filter WmiMethodErrorCheck {
    if($_.ReturnValue -eq 0) {
        $_
    } else {
        Write-Error ([System.Runtime.InteropServices.Marshal]::GetExceptionForHR([BitConverter]::ToInt32([BitConverter]::GetBytes($_.ReturnValue), 0)))
    }
}
 
$printer = Get-CimInstance Win32_Printer
$printer |% {
    $sd = (Invoke-CimMethod -InputObject $_ -MethodName GetSecurityDescriptor | WmiMethodErrorCheck).Descriptor

    $acl = New-Object System.Collections.Generic.List[CimInstance]
    $acl.AddRange($sd.DACL)

    $trustee = New-Object CimInstance (Get-CimClass Win32_Trustee)
    $trustee.Domain = 'NT AUTHORITY'
    $trustee.Name = 'Authenticated Users'

    $ace = New-Object CimInstance (Get-CimClass Win32_ACE) -Property @{
        AccessMask = 0x000f000c
        AceFlags   = [System.Security.AccessControl.AceFlags]::None
        AceType    = [System.Security.AccessControl.AceType]::AccessAllowed
        Trustee    = $trustee
    }
    $acl.Add($ace)

    $ace = New-Object CimInstance (Get-CimClass Win32_ACE) -Property @{
        AccessMask = 0x000f0030
        AceFlags   = ([System.Security.AccessControl.AceFlags] 'InheritOnly, ObjectInherit')
        AceType    = [System.Security.AccessControl.AceType]::AccessAllowed
        Trustee    = $trustee
    }
    $acl.Add($ace)

    $sd.DACL = $acl

    Invoke-CimMethod -InputObject $_ -MethodName SetSecurityDescriptor -Arguments @{Descriptor = $sd} | WmiMethodErrorCheck | Out-Null
}
