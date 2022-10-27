sudo useradd -m doorserver
sudo passwd doorserver
cd /home/doorserver #change directory
sudo apt-get install git
git clone https://github.com/OhioDschungel6/NFC_Server.git
cd NFC_Server
sudo adduser doorserver gpio
sudo apt-get install pip
pip install virtualenv
virtualenv -p python3 doorEnvironment
source doorEnvironment/bin/activate


cp ./doorserver.service /etc/systemd/system/doorserver.service
sudo systemctl start doorserver    # Runs the script now
sudo systemctl enable doorserver #Adds the script as service