# Zero Trust Architecture with Blockchain virtual lab

## Project setup

Ubuntu 18.04 is currently used for the development environment. Make project setup executable script

```sh
# clone and enter repository
$ git clone https://github.com/aalmeida9/ZT-BC-lab --recursive
# if you cloned the repository without --recursive run:
# git submodule update --init --recursive
$ cd ZT-BC-lab
# setup and enter python virtual environment (optional)
$ python3 -m venv venv
$ source venv/bin/activate
# install required python packages
$ pip install -e .
# Install Mininet
$ sudo apt-get install mininet
# Install Ryu
$ cd ryu; pip install .
```

## Flask Applications

The frontend web server and Blockchain application use the Flask microframework. The implementation of Blockchain is based on this repository: https://github.com/satwikkansal/python_blockchain_app/tree/ibm_blockchain_post

Each of the following blocks of commands need to be run in different terminals in order for the project to work properly.

### Blockchain startup

```sh
$ python runBC.py
```

### Frontend Web server

```sh
$ python runFrontend.py
```

## Network

### Network Emulation

Network emulation uses Mininet. More information can be found here: http://mininet.org/

```sh
# Run network emulation and create topology from command line
$ sudo mn --topo single,3 --mac --switch ovsk --controller remote
# Run net from file, new
$ sudo python net.py
```

### Software Defined Networking (SDN) Controller

SDN controller currently uses the Ryu framework for the firewall application. More information can be found here: https://ryu-sdn.org/

```sh
# switching to SSO.py
$ ryu-manager ryu.app.rest_firewall # possibly include: ryu.app.ofctl_rest
```
