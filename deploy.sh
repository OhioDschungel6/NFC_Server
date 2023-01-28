sudo useradd -m doorserver
sudo passwd doorserver

sudo apt-get install git
sudo apt-get install python3-rpi.gpio
sudo adduser doorserver gpio
sudo apt-get install pip
pip install virtualenv
sudo su doorserver && bash

cd /home/doorserver #change directory
git clone https://github.com/OhioDschungel6/NFC_Server.git
cd NFC_Server

virtualenv -p python3 doorEnvironment --system-site-packages
source doorEnvironment/bin/activate
pip install -r requirements.txt
exit


cd /home/doorserver/NFC_Server
sudo cp ./doorserver.service /etc/systemd/system/doorserver.service
sudo systemctl start doorserver    # Runs the script now
sudo systemctl enable doorserver #Adds the script as service

#Change config and restart!