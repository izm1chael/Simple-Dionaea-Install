# Simple Dionaea Install
This script automates the installation of Dionaea Honey Pot, in order to use follow the instructions below. 

***This Will Only Work on Debian/Ubuntu Based System and has been Tested on Ubuntu 16.04 (Dionaea Recommended)***

The default dionaea.cfg is also edited in order to reduce the amount of logs the application creates, this will help to reduce the volume of data on your system that is not relevant to the honeypot or malware capture

	git clone https://github.com/izm1chael/Simple-Dionaea-Install.git
	cd Simple-Dionaea-Install
	sudo bash dionaea-install.sh

## Included Options

 - log_incident
 - log_json
 - hpfeeds
 - [Cyber Bytes Bistreams Rotation](https://github.com/izm1chael/Dionaea-Bistream-Rotation)

Feel free to request further options

