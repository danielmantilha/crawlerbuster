This script runs on server side and captures ip's who are making too many GET requests based on apache2's logs and drops all incoming packages from them using iptables (banning them).

It parses the logs for bad actors, extracting their ip's and timestamps, where it generates an entry for that ip with the current timestamp,
it then compares the timestamps and makes sure only timestamps within the window parameter are present in the deque
if the deque surpasses the threshold it blocks the ip using iptables.

You can set keywords you want to look for in the lines and ban bad actors intantly, like "/admin.php"
etc

Start by configuring the config.ini to Adjust Params to your liking
```
log_path = (the path to your apache2 access.log, default value already set)
window = (window size in seconds) 
threshold = (total get requests allowed within window)
ban_duration = (logic not implemented yet)
safe_ip_list = (one big string separated by empty spaces "example1.ip.1 example2.ip.2 example3.ip.3")
keywords = (one big string separated by empty spaces "/critical /admin /someotherkeyword")
```
Here are some illustrative examples of time window and threshold params for different services:
```

Small personal blog:

Window Size: 300 seconds (5 minutes)

Threshold: 100 requests (a normal user might hit 20-30 pages in 5 minutes, so 100 gives a good buffer).

Medium e-commerce site:

Window Size: 60 seconds (1 minute)

Threshold: 200 requests (due to more assets per page, searching, filtering, etc.).

API endpoint with heavy usage:

Window Size: 10 seconds

Threshold: 50 requests (API calls can be rapid, but consistent high volume from one IP could indicate abuse)
```

The best approach is to run it as a service, so do as follows  

create a service entry 
```
sudo nano /etc/systemd/system/crawlerbuster.service
```

paste this in the .service file you just created (DON'T FORGET TO CHANGE the Script's path, your Username and Working directory)
```
[Unit]
Description=CrawlerBuster Apache Log Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /PATH/TO/crawlerbuster.py
WorkingDirectory=/PATH/TO/crawlerbuster.py 
Restart=on-failure
StandardOutput=journal
StandardError=journal
User=<YOUR_USER_HERE>

[Install]
WantedBy=multi-user.target
```
add your user to be able to run iptables without password
```
sudo visudo

yourusername ALL=(ALL) NOPASSWD: /sbin/iptables

```
then run
```
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable crawlerbuster.service
sudo systemctl start crawlerbuster.service
```

<<>>IP REPORTING FEATURE <<>>

if you want to report ips for blacklisting and contribute to the security of the web, 
register an api key at https://www.abuseipdb.com/account/api
then, 
insert your api-key on config.ini file.

enter the project's folder then create virtual enviroment, activate it and install requests module

```
python -m venv venv
source venv/bin/activate
pip install requests 
```
You're Done! -
Created by Daniel Mantilha -
If you like this project and want to contribute get in touch.
daniel.mantilha@gmail.com






