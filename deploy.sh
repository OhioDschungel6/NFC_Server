sudo useradd -m doorserver
sudo passwd doorserver

sudo apt-get install git
sudo apt-get install python3-rpi.gpio
sudo adduser doorserver gpio
sudo apt-get install pip

sudo su doorserver

cd /home/doorserver #change directory
#sudo chown -R doorserver:doorserver NFC_Server
git clone https://github.com/OhioDschungel6/NFC_Server.git
cd NFC_Server

pip install virtualenv
virtualenv -p python3 doorEnvironment
source doorEnvironment/bin/activate
pip install -r requirements.txt
exit

sudo cp ./doorserver.service /etc/systemd/system/doorserver.service
sudo systemctl start doorserver    # Runs the script now
sudo systemctl enable doorserver #Adds the script as service