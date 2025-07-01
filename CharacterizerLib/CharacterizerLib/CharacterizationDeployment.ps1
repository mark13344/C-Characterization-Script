$code = get-content .\Characterizer.cs -Raw
Add-type -TypeDefinition $code -ReferencedAssemblies "System.Management.dll"
Add-Type -AssemblyName System.Security
Add-Type -TypeDefinition $code -Language CSharp
$machine = New-Object Characterizer+ProcessInfo
