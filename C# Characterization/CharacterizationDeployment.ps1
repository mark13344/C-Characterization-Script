$code = get-content .\Characterizer.cs -Raw
Add-Type -TypeDefinition $code -Language CSharp
$machine = New-Object MachineInfo
