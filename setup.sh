# sudo check
if [ "$EUID" -ne 0 ]; then
	echo "Please run this script with sudo privilege"
	exit
fi

# init
reboot=0
RUSER=$(logname)
cd /home/$RUSER
apt-get update
apt-get install python-pip python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev g++ wget -y
sudo -H pip install --upgrade pip
sudo -H pip install lockfile --upgrade
sudo -H pip install Appium-Python-Client

# install java
if ! command -v java > /dev/null; then
	apt-get install openjdk-8-jdk -y
	echo "export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64" >> /etc/profile.d/mobitec.sh
	echo "export PATH=\$PATH:\$JAVA_HOME/bin" >> /etc/profile.d/mobitec.sh
fi

# install latest npm and 9.8.0 node
if ! command -v node > /dev/null || ! command -v npm > /dev/null; then
	apt-get install nodejs -y
	npm install npm@latest -g
	npm cache clean -f
	npm install -g n
	n 9.8.0
	ln -sf /usr/local/n/versions/node/9.8.0/bin/node /usr/bin/nodejs
	apt-get remove nodejs -y
	hash -r
fi

# install 2.12.0 genymotion
if ! command -v gmtool > /dev/null && ! /opt/genymotion/gmtool version 2>/dev/null 1>/dev/null; then
	apt install virtualbox -y
	wget "https://dl.genymotion.com/releases/genymotion-2.12.0/genymotion-2.12.0-linux_x64.bin"
	echo 'y' | sudo bash genymotion-2.12.0-linux_x64.bin --destination /opt
	rm genymotion-2.12.0-linux_x64.bin
	echo "export PATH=\$PATH:/opt/genymotion/" >> /etc/profile.d/mobitec.sh
	reboot=1
fi

# install android-sdk-linux
if ! command -v android > /dev/null && ! /opt/android-sdk-linux/tools/android list sdk > /dev/null; then
	wget "http://dl.google.com/android/android-sdk_r24.0.2-linux.tgz"
	tar -xvf android-sdk_r24.0.2-linux.tgz
	rm android-sdk_r24.0.2-linux.tgz
	mv android-sdk-linux /opt/android-sdk-linux
	/opt/android-sdk-linux/tools/android update sdk
	echo "export ANDROID_HOME=/opt/android-sdk-linux" >> /etc/profile.d/mobitec.sh
	echo "export PATH=\$PATH:\$ANDROID_HOME/tools:\$ANDROID_HOME/platform-tools:\$ANDROID_HOME/build-tools/23.0.1" >> /etc/profile.d/mobitec.sh
	reboot=1
fi

# install appium
if ! command -v appium > /dev/null && ! /usr/local/bin/appium --version 2>/dev/null 1>/dev/null; then
	echo 'Prepare to install appium'
	npm install -g appium --unsafe-perm=true --allow-root
	npm install -g appium-doctor
fi

# install pip
if ! command -v pip > /dev/null; then
	apt-get install python-pip -y
fi

# insoall mitmproxy 0.18.2
if ! command -v mitmproxy > /dev/null; then
	sudo -H pip install mitmproxy==0.18.2
fi

# install pymodel
if ! command -v pmt > /dev/null; then
	sudo -H pip install pymodel
	TMPPATH=$(python -c "import site; print(site.getsitepackages()[0])")
	sudo echo "export PYTHONPATH=$TMPPATH/pymodel" >> /etc/profile.d/mobitec.sh
	reboot=1
fi

# purge useless installations
chmod -R 777 /usr/local/lib/node_modules/appium
apt autoremove -y
apt-get clean

# require reboot
if [ "$reboot" == "1" ]; then
	echo "Reboot is required to finish setup"
	echo -e "Reboot now? (y/n) \c"
	read
	if [ "$REPLY" == "y" ]; then
		echo 'Rebooting...'
		reboot
	fi
fi
