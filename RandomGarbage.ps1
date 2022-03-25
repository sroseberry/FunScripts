<#
#Key Gen
$GeneratedKey=""
foreach ($byte in (Get-Random -Count 32 -InputObject (0..255))){
  $GeneratedKey+=$byte.tostring()+","
}
#RegEx to remove last char
$GeneratedKey = $GeneratedKey -replace ".$"

#>

[Byte[]]$Key = 92,61,222,194,21,235,184,167,127,98,189,30,176,155,94,63,25,227,82,36,9,246,157,239,163,226,6,38,150,118,251,46
