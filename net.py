"""
A simple minimal topology script for Mininet.
From: https://inside-openflow.com/2016/06/29/custom-mininet-topologies-and-introducing-atom/

Based in part on examples in the [Introduction to Mininet] page on the Mininet's
project wiki.

[Introduction to Mininet]: https://github.com/mininet/mininet/wiki/Introduction-to-Mininet#apilevels

Need to make a superclass of the node/host class and add info for authentication
"""

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo #MultiGraph tracks topology changes
from mininet.node import RemoteController, OVSSwitch

# Resources:
# API reference manual
# http://mininet.org/api/classmininet_1_1topo_1_1Topo.html

# Run a simple web server and client
# http://mininet.org/walkthrough/#display-startup-options

# Flow analytics
# https://blog.sflow.com/2019/06/mininet-flow-analytics-with-custom.html

# Running processes on the nodes
# https://github.com/mininet/mininet/wiki/Introduction-to-Mininet#creating-topologies

# Superclass of node for additional attributes, not working
# class secureHost( addHost ):
#     def __init__(self, password):
#         self.password = password
#         #Not sure if correct
#         super(secureHost, self).__init__()

class MinimalTopo( Topo ):
    "Minimal topology with a single switch and two hosts"
    # Consider using LinearTopo
    def build( self ):
        # Create two hosts.
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )

        # Create a switch
        s1 = self.addSwitch( 's1' )

        # Add links between the switch and each host
        self.addLink( s1, h1 )
        self.addLink( s1, h2 )

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

    # Actually start the network
    net.start()

    # Drop the user in to a CLI so user can run commands.
    CLI( net )

    # After the user exits the CLI, shutdown the network.
    net.stop()

if __name__ == '__main__':
    # This runs if this file is executed directly
    setLogLevel( 'info' ) # can also use 'debug'
    runMinimalTopo()

# Allows the file to be imported using `mn --custom <filename> --topo minimal`
topos = {
    'minimal': MinimalTopo
}