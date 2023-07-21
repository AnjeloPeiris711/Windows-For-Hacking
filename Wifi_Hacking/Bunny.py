import os
import scapy
import argparse

class Bunny:
    def __init__(self):
        print("""
        (\_/)
        (. .) BUNNY!
        C('')('') 
        """)
#Check which WiFi adapter supports monitor mode
class CheckInterface:
    def __init__(self):
        self.interface_name = None
        self.description = None
        self.monitor = None
        self.name = None
    def wirelesscapabilities(self):
        self.interface_name = os.popen("""netsh wlan show wirelesscapabilities | findstr /C:"Interface name" | for /F "tokens=3" %i in ('findstr /R /C:"^Interface name:"') do @echo %i""").read()
    # def interfaces(self):
    #     self.name = os.popen("""for /f "tokens=2 delims=:" %G in ('netsh wlan show interfaces ^| findstr /C:"Name"') do @echo %G""").read()
    def compair(self):
        #self.wirelesscapabilities()
        print(os.popen('netsh wlan show wirelesscapabilities | findstr /C:"Interface name" /C:"monitor"').read())
        # self.interfaces()
        # if(self.interface_name.strip() == self.name.strip()):
        #     InterfacesData = 
        # else:
        #     print(self.name)
        #     print(self.interface_name)
checkin = CheckInterface()
class SelectInterface:
    def __init__(self):
        raise NotImplementedError("Select -i")
class InablemonitorMood:
    def __init__(self) -> None:
        pass
class Scan:
    def __init__(self) -> None:
        pass
class Commands:
    def __init__(self):
        parser = argparse.ArgumentParser(prog='Bunny', description='Wifi Hacking Tool for Windows')

        # Create a sub-parser for the commands
        subparsers = parser.add_subparsers(title='Commands', metavar='')

        # Install command
        install_parser = subparsers.add_parser('install', help='Install packages.')
        # Add install command-specific options if needed

        # Download command
        download_parser = subparsers.add_parser('download', help='Download packages.')
        # Add download command-specific options if needed

        # Add more commands with their respective options

        # General options
        parser.add_argument('-c', '--check', action='count', help='Check which WiFi adapter supports monitor mode.')
        parser.add_argument('-V', '--version', action='store_true', help='Show version and exit.')
        parser.add_argument('-q', '--quiet', action='count', help='Give less output. Option is additive, and can be used up to 3 times (corresponding to WARNING, ERROR, and CRITICAL logging levels).')
        parser.add_argument('-i', '--interface', action='count', help='Select interface using Name.')
        parser.add_argument('-m', '--monitor', action='count', help='Enable monitor mood.')
        parser.add_argument('-s', '--scan', action='count', help='Scan the Network.')
        parser.add_argument('-f', '--file', action='count', help='File name && Save file.')
        # Parse the arguments
        args = parser.parse_args()
        # Check if the  flag is set
        match True:
            case args.check:
                # print(os.popen('netsh wlan show wirelesscapabilities | findstr monitor').read())
                checkin.compair()
            case args.version:
                print("0.01")
            case args.interface:
                SelectInterface()
            case _:
                Bunny()
if __name__ == "__main__":
    commands = Commands()
