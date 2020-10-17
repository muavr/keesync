#!/bin/bash

set -e

read -p "Application key: " APP_KEY
read -p "Keepass database path: " DATABASE_PATH
DATABASE_PATH=`realpath ${DATABASE_PATH}`

USER=`whoami`
PYTHON="python3"
WORKING_DIRECTORY="/home/${USER}/.keesync"
CURRENT_DIR=`pwd`

echo "Create working directory"
mkdir -p ${WORKING_DIRECTORY}
cp ./keesync.py ${WORKING_DIRECTORY}
cd ${WORKING_DIRECTORY}

echo "Create virtual environment"
${PYTHON} -m venv env
source ./env/bin/activate
PYTHON_PATH=`which python`

echo "Install requirements"
pip install -U pip
pip install -r ${CURRENT_DIR}/requirements.txt

echo "Initialize application"
rm -f ${WORKING_DIRECTORY}/.token
python keesync.py -a ${APP_KEY} -p ${DATABASE_PATH} --init

echo "Create service"
cp ${CURRENT_DIR}/keesync.service ${CURRENT_DIR}/_keesync.service
sed -i "s@{USER}@${USER}@g" ${CURRENT_DIR}/_keesync.service
sed -i "s@{WORKING_DIRECTORY}@${WORKING_DIRECTORY}@g" ${CURRENT_DIR}/_keesync.service
sed -i "s@{PYTHON_PATH}@${PYTHON_PATH}@g" ${CURRENT_DIR}/_keesync.service
sed -i "s@{DATABASE_PATH}@${DATABASE_PATH}@g" ${CURRENT_DIR}/_keesync.service
sed -i "s@{APP_KEY}@${APP_KEY}@g" ${CURRENT_DIR}/_keesync.service

sudo cp ${CURRENT_DIR}/_keesync.service ${WORKING_DIRECTORY}/keesync.service
rm ${CURRENT_DIR}/_keesync.service
sudo ln -fs ${WORKING_DIRECTORY}/keesync.service  /etc/systemd/system/keesync.service

sudo systemctl unmask keesync
sudo systemctl daemon-reload
sudo systemctl start keesync
sudo systemctl enable keesync
