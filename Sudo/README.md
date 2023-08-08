# Sudo for Windows

## what is sudo command in linux

The sudo command ```provides an efficient way to grant users the special rights to execute commands at the system (root) level```. With sudo, we'll be able to execute administrative tasks without switching users.

## Can i use It Windows

There is no sudo command in Windows. The nearest equivalent is ```run as administrator```You can do this using the runas command with an administrator trust-level, or by right-clicking the program in the UI and choosing "run as administrator."

Use bat file

```
@echo off
powershell -Command "Start-Process cmd -Verb RunAs -ArgumentList '/k cd /d %CD% && %*'"
@echo on

```