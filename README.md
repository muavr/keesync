Keesync - application is based on dropbox API that allows to synchronize keepass db.
This tiny app is for who do not want to install full dropbox application on Linux machine.

The app upload keepass db file to dropbox server if file is changed on the client side.
If file is changed on the server side the app download file to the client side.
Database is stored into the directory /App/\<your application name\>/ on dropbox server.

To create dropbox application go [here](https://www.dropbox.com/developers/apps?_tk=pilot_lp&_ad=topbar4&_camp=myapps).
You have to register an account on dropbox if you have not.
Then application  will be created write down an app key it will be necessary later.
On Permission tab mark as true the following minimal set of permissions:
- account_info.read
- files.metadata.write
- files.metadata.read
- files.content.write
- files.content.read

## Installation
```shell script
git clone https://github.com/muavr/keesync.git
cd ./keesync
./install.sh
```
During installation you will be requested
- application path
- path to your database
- authorization code

To get authorization code you have to go authorization url that will be created during installation process.

In result the application will be installed in ~/.keesync directory in your $HOME.
It will create virtual environment in ~/.keesync.
During installation the application gets refresh token that uses to get short living access token.
The app creats service unit on /etc/systemd/system/keesync.service.


## Main requirements
- linux
- python3
- python3-venv
- dropbox
- requests

## Manual usage
```shell script
python ./keesync.py -h
usage: keesync [-h] [-v] [-a APP] -p PATH [-s SLEEP]
               [-l {debug,info,warning,error,critical}] [-i]

Synchronize keepass database through dropbox.

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -a APP, --app APP     application key
  -p PATH, --path PATH  path to keepass database
  -s SLEEP, --sleep SLEEP
                        time interval in seconds before he next iteration of
                        synchronization
  -l {debug,info,warning,error,critical}, --log {debug,info,warning,error,critical}
                        logging level
  -i, --init            initialize application - generate refresh token
```

In case, the app key is omitted the app wil try read app key from the KEESYNC_APP_KEY environment variable.

## Update
To update script only use
```shell script
./install.sh -u
```
