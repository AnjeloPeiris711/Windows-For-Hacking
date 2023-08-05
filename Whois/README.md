# Whois Command For Windows

In Linux, whois command is used to find out the information about a domain, such as the owner of the domain, the owner’s contact information, and the name servers that the domain is using.

It allows you to perform lookup of owner information of a website by querying databases that store the registered users of a domain or IP address.

But if you try to run the same command on a Windows machine, you will face the following error:

```
 C:\Users\🦊>whois youtube.com
'whois' is not recognized as an internal or external command,
operable program or batch file.

```
In order to resolve the ‘whois’ not recognized, we need to manually install a Whois program.

Let’s do it. After installation and adding path, It will work on any version of Windows 

### Please follow these steps to use the "Whois" tool 😯

Step 1: [Download Whois Program](https://learn.microsoft.com/en-us/sysinternals/downloads/whois) from Microsoft’s site.

Step 2: Create a folder in your computer( eg. whois) and Extract the content of the downloaded zip file to your created folder.

Step 3: You will find whois.exe and whois64.exe under your extracted location. In my case it is L:\whois\whois.exe and L:\whois\whois64.exe

```
Adding the your ‘whois’ directory path to Windows system PATH

```
Step 4: Open System in Control Panel — -> Go to Advanced System Settings — -> Click on Environment Variables —> Define a new System Variable with PATH=L:\whois

Step 5: Close and reopen your command prompt for allowing the changes to take place. Now, you will be able to run the WHOIS command from any path inside command prompt.

Syntax :-
```
🦊> whois.exe [-v] domainname [whois.server]

```
Example : —
```
🦊>whois google.com 

```