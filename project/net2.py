"""
A simple minimal topology script for Mininet.
From: https://inside-openflow.com/2016/06/29/custom-mininet-topologies-and-introducing-atom/

Based in part on examples in the [Introduction to Mininet] page on the Mininet's
project wiki.

[Introduction to Mininet]: https://github.com/mininet/mininet/wiki/Introduction-to-Mininet#apilevels
"""

import requests
import json


from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.util import dumpNodeConnections

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch


# Resources:
# Running processes on the nodes, really useful intro to mininet
# https://github.com/mininet/mininet/wiki/Introduction-to-Mininet#creating-topologies

# Run a simple web server and client
# http://mininet.org/walkthrough/#display-startup-options

# Flow analytics
# https://blog.sflow.com/2019/06/mininet-flow-analytics-with-custom.html

class MinimalTopo( Topo ):
    "Minimal topology with a single switch and 5 hosts"

    def build( self ):
        # Create 5 hosts.
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        h4 = self.addHost( 'h4' )
        h5 = self.addHost( 'h5' )

        # Create a switch
        s1 = self.addSwitch( 's1' )

        # Add links between the switch and each host
        self.addLink( s1, h1 )
        self.addLink( s1, h2 )
        self.addLink( s1, h3 )
        self.addLink( s1, h4 )
        self.addLink( s1, h5 )


def runMinimalTopo():
    "Bootstrap a Mininet network using the Minimal Topology"

    # Create an instance of our topology
    topo = MinimalTopo()

    # Create a network based on the topology using OVS and controlled by
    # a remote controller.
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController( name, ip='127.0.0.1' ),
        switch=OVSSwitch,
        autoSetMacs=True )

    # start the network
    net.start()

    # Interesting
    # print("Dumping host connections")
    # connections = dumpNodeConnections(net.hosts)
    # result = h1.cmd('ifconfig')
    # print(result)
    #pid = int( h1.cmd('echo $!') )
    #h1.cmd('wait', pid)

    hosts = net.hosts

    for h in hosts:
        #create JSON object of host: ip
        ip = json.dumps({
            #"index": index(h),
            "host": h.name,
            "ip": h.IP(),
            "mac": h.MAC()})

        #send host POST request
        response = requests.post('http://0.0.0.0:5000/getHost', json=ip,
        headers={'Content-type': 'application/json'})
        #Exit if request isn't properly executed
        if(response.status_code != 200 or response.text != "0"):
            print("Error sending host/ip configurations to frontned")
            print(response.status_code)
            net.stop()

    # Drop the user in to a CLI so user can run commands.
    CLI( net )

    # After the user exits the CLI, shutdown the network.
    net.stop()

if __name__ == '__main__':
    # This runs if this file is executed directly, can also use 'debug'
    setLogLevel( 'info' )
    runMinimalTopo()

# Allows the file to be imported using `mn --custom <filename> --topo minimal`
topos = {
    'minimal': MinimalTopo
}
