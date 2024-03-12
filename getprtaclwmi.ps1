<#
.SYNOPSIS
List access control entries of all printers.
.NOTES
Get printer acl by wmi ver 1.00

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

$aceparser = @{
    Property = @(
        @{Name='AceType'; Expression={[System.Security.AccessControl.AceType] $_.AceType}},
        @{Name='Domain'; Expression={$_.Trustee.Domain}},
        @{Name='Name'; Expression={$_.Trustee.Name}},
        @{Name='Sid'; Expression={$_.Trustee.SIDString}},
        @{Name='AceFlags'; Expression={[System.Security.AccessControl.AceFlags] $_.AceFlags}},
        @{Name='AccessMask'; Expression={'0x{0:x8}' -f $_.AccessMask}})
}

$printer = Get-WmiObject Win32_Printer
$printer |% {
    $_.Name | Out-Default
    $sd = ($_.GetSecurityDescriptor() | WmiMethodErrorCheck).Descriptor
    
    $acl = New-Object System.Collections.Generic.List[System.Management.ManagementBaseObject]
    $acl.AddRange($sd.DACL)
    
    $acl | Select-Object @aceparser | ft AceType, Name, AceFlags, AccessMask | Out-Default
}
