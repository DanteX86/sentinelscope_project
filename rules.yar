/*
    SentinelScope YARA Rules
    Basic malware detection rules
*/

rule SuspiciousExecutable
{
    meta:
        description = "Detects suspicious executable patterns"
        author = "SentinelScope"
        severity = "medium"
        
    strings:
        $mz = { 4D 5A }  // MZ header
        $pe = "PE"
        $suspicious1 = "keylogger" nocase
        $suspicious2 = "backdoor" nocase
        $suspicious3 = "trojan" nocase
        
    condition:
        $mz at 0 and $pe and any of ($suspicious*)
}

rule PotentialMalware
{
    meta:
        description = "Detects potential malware strings"
        author = "SentinelScope"
        severity = "high"
        
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $reg1 = "regedit" nocase
        $net1 = "netsh" nocase
        $sys1 = "system32" nocase
        $temp = "%temp%" nocase
        
    condition:
        3 of them
}

rule SuspiciousScript
{
    meta:
        description = "Detects suspicious script patterns"
        author = "SentinelScope"
        severity = "medium"
        
    strings:
        $script1 = "eval(" nocase
        $script2 = "document.write" nocase
        $script3 = "unescape(" nocase
        $script4 = "fromCharCode" nocase
        $obfusc1 = /[a-zA-Z0-9+\/]{50,}/ // base64-like patterns
        
    condition:
        2 of ($script*) or $obfusc1
}

rule NetworkActivity
{
    meta:
        description = "Detects suspicious network activity patterns"
        author = "SentinelScope"
        severity = "medium"
        
    strings:
        $url1 = "http://" nocase
        $url2 = "https://" nocase
        $ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        $download = "download" nocase
        $upload = "upload" nocase
        
    condition:
        ($url1 or $url2 or $ip) and ($download or $upload)
}

rule PasswordHarvesting
{
    meta:
        description = "Detects password harvesting attempts"
        author = "SentinelScope"
        severity = "high"
        
    strings:
        $pass1 = "password" nocase
        $pass2 = "passwd" nocase
        $cred1 = "credential" nocase
        $login1 = "login" nocase
        $auth1 = "authentication" nocase
        $steal = "steal" nocase
        $harvest = "harvest" nocase
        
    condition:
        2 of ($pass*) and (any of ($cred*, $login*, $auth*)) and ($steal or $harvest)
}

rule CryptocurrencyMiner
{
    meta:
        description = "Detects cryptocurrency mining software"
        author = "SentinelScope"
        severity = "medium"
        
    strings:
        $crypto1 = "bitcoin" nocase
        $crypto2 = "ethereum" nocase
        $crypto3 = "monero" nocase
        $mining1 = "mining" nocase
        $mining2 = "miner" nocase
        $pool = "pool" nocase
        $stratum = "stratum" nocase
        
    condition:
        any of ($crypto*) and any of ($mining*) and ($pool or $stratum)
}

rule RansomwarePatterns
{
    meta:
        description = "Detects potential ransomware patterns"
        author = "SentinelScope"
        severity = "critical"
        
    strings:
        $ransom1 = "ransom" nocase
        $encrypt1 = "encrypt" nocase
        $decrypt1 = "decrypt" nocase
        $bitcoin1 = "bitcoin" nocase
        $payment1 = "payment" nocase
        $file_ext1 = ".locked"
        $file_ext2 = ".encrypted"
        $readme = "README" nocase
        
    condition:
        ($ransom1 or ($encrypt1 and $decrypt1)) and ($bitcoin1 or $payment1) and (any of ($file_ext*) or $readme)
}
