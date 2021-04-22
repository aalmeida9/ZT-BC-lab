# Zero Trust Architecture with Blockchain virtual lab

This project utilizes Ubuntu 18.04 for the development environment.

### Manual Setup
```sh
# Update and upgrade Ubuntu
$ sudo apt-get update
$ sudo apt-get upgrade
# Install project dependencies
$ sudo apt-get install git python-pip mininet python3-ryu
# Clone repository and initialize Ryu submodule (not needed)
$ git clone https://github.com/aalmeida9/ZT-BC-lab --recursive
# Enter repository folder and install python dependencies
$ cd ZT-BC-lab
$ pip install -e .
$ cd project; sudo python run
```

## Project Startup

The frontend web server and Blockchain application use the Flask microframework.
 The implementation of Blockchain is based on this repository:
 https://github.com/satwikkansal/python_blockchain_app/tree/ibm_blockchain_post

### Frontend Web server

The rest of the project systems can be started from the frontend via the startup
page. In order to start the frontend run the following commands:

 ```sh
 $ cd project
 # Use sudo to avoid repeating password entry during startup of other applications
 $ sudo python runFrontend.py
 ```

## Manual Startup

The different project systems can also be started seperately, which is helpful
for testing and debugging. Each of the following blocks of commands need to be
run in different terminals in order for the project to work properly.

### Blockchain startup

```sh
$ python runBC.py
```

## Network

### Network Emulation

Network emulation uses Mininet. Two network scripts can be executed via the
frontend inside the startup page. Alternatively
More information can be found here: http://mininet.org/

```sh
# Run network emulation and create topology from command line
$ sudo mn --topo single,3 --mac --switch ovsk --controller remote
# Run net from file, new
$ sudo python net.py
```

### Software Defined Networking (SDN) Controller

SDN controller currently uses the Ryu framework for the firewall application.
More information can be found here: https://ryu-sdn.org/

```sh
# Default Ryu applications can be run with: ryu-manager ryu.app.RYU_APP_NAME
# Firewall Application:
$ ryu-manager rest_firewall.py
# Single Sign-On Application:
$ ryu-manager rest_sso.py
```
