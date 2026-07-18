rule Aria_EICAR_Test_File
{
    meta:
        description = "EICAR standard antivirus test string"
        author = "Aria Security"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
