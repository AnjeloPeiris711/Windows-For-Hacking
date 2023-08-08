# apt-get update & upgrade For Windows

## apt-get update vs upgrade – What is the Difference?

``` sudo apt-get update ``` and ```sudo apt-get upgrade ``` are two commands you can use to keep all of your packages up to date in Debian or a Debian-based Linux distribution.

The main difference is that ``` sudo apt-get update ``` fetches the latest version of the package list from your distro's software repository, and any third-party repositories you may have configured. In other words, it'll figure out what the latest version of each package and dependency is, but will not actually download or install any of those updates.

The ``` sudo apt-get upgrade ``` command downloads and installs the updates for each outdated package and dependency on your system. But just running ``` sudo apt-get upgrade ``` will not automatically upgrade the outdated packages – you'll still have a chance to review the changes and confirm that you want to perform the upgrades.

## upgrade command (winget)

The upgrade command of the ```winget```  tool upgrades the specified application. Optionally, you may use the list command to identify the application you want to upgrade.

The upgrade command requires that you specify the exact string to upgrade. If there is any ambiguity, you will be prompted to further filter the upgrade command to an exact application.

### Usage
Syntax :-
```
🦊> winget upgrade [[-q] \<query>] [\<options>]

```
Example : —
```
🦊> winget upgrade powertoys

```

```
🦊> winget list terminal 

```

```
🦊> winget upgrade --all

```
