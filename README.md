#### see my post in [LinkedIn](https://www.linkedin.com/posts/anjelo-peiris-522069230_windows-for-hackers-can-we-use-windows-activity-7089074389916258304-gY2i?utm_source=share&utm_medium=member_desktop)
## How To Use Windows As A Hackers Operating System

## Can we use windows OS as a hacking platform?
  Yes, you can use Windows as a platform to learn and practice ethical hacking or cyber security skills. Actually, you can make any OS your platform,     so you should have an understanding of the functionality of the platform you are using. But you already know that there are some operating systems      that are specially designed for hacking. They are built by understanding the combination of hardware and software. This attempt of mine is to           understand Windows. 🥴😏😈



# Episode 1

![Wi-Fi Hacking](https://github.com/AnjeloPeiris711/Windows-For-Hacking/assets/51872510/31609c6e-c300-4ef7-8b08-5aef9f0dc6c2)

Project:- https://github.com/AnjeloPeiris711/Windows-For-Hacking/tree/main/Wifi_Hacking/bunny
Demo :- https://www.youtube.com/watch?v=TJDcy3PpD1g
Lsusb :- https://www.youtube.com/watch?v=GnmjhyQfYw0
### Network scan
for ($i = 1; $i -le 254; $i++) {
  Test-Connection -ComputerName "192.168.1.$i" -Count 1 -ErrorAction SilentlyContinue | Where-Object { $_.StatusCode -eq 0 }
}
