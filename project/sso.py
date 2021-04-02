# rest api not currently working
import json

from ryu.app import simple_switch_13
#from webob import Response
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase, Response, WSGIApplication, route
from ryu.lib import dpid as dpid_lib

simple_switch_instance_name = 'simple_switch_api_app'
mac_url = '/simpleswitch/mactable/{dpid}'
role_url = '/simpleswitch/roletable/{dpid}'

# extension of SimpleSwitch13 Ryu component, from app_manager.RyuApp
class SimpleSwitchRest13(simple_switch_13.SimpleSwitch13):

    # dpset.DPset?
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchRest13, self).__init__(*args, **kwargs)
        self.switches = {}
        self.mac_to_role = {}
        # or role to mac(s), might be more difficult to implement
        wsgi = kwargs['wsgi']
        # Registers the Controler class for WSGI
        wsgi.register(SimpleSwitchController,
                      {simple_switch_instance_name: self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        super(SimpleSwitchRest13, self).switch_features_handler(ev)
        print("Ev: {}".format(ev.msg))
        datapath = ev.msg.datapath
        self.switches[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_role.setdefault(datapath.id, {})

    def set_mac_to_port(self, dpid, entry):
        mac_table = self.mac_to_port.setdefault(dpid, {})
        role_table = self.mac_to_role.setdefault(dpid, {})
        datapath = self.switches.get(dpid)

        entry_port = entry['port']
        entry_mac = entry['mac']
        entry_role = entry['role']
        print(entry_role)

        if datapath is not None:
            parser = datapath.ofproto_parser
            if entry_port not in mac_table.values():

                for mac, port in mac_table.items():

                    # from known device to new device
                    actions = [parser.OFPActionOutput(entry_port)]
                    match = parser.OFPMatch(in_port=port, eth_dst=entry_mac)
                    self.add_flow(datapath, 1, match, actions)
                    #add_flow method from parent Simple Switch class

                    # from new device to known device
                    actions = [parser.OFPActionOutput(port)]
                    match = parser.OFPMatch(in_port=entry_port, eth_dst=mac)
                    self.add_flow(datapath, 1, match, actions)

                mac_table.update({entry_mac: entry_port})
                role_table.update({entry_mac: entry_role})
        return mac_table

    # Funciton for setting roles, Worker: 0, Admin: 1, Server: 2
    # 0 to 1 and 1 to 0, 1 to 2 and 2 to 1
    # Set and print role
    def set_mac_to_role(self, dpid, entry):
        role_table = self.mac_to_role.setdefault(dpid, {})
        mac_table = self.mac_to_port.setdefault(dpid, {})
        datapath = self.switches.get(dpid)

        entry_port = entry['port']
        entry_mac = entry['mac']
        entry_role = entry['role']

        if datapath is not None:
            parser = datapath.ofproto_parser
            if entry_mac not in role_table.values():
                for role, port in role_table.items():
                    if(entry_role == 1):
                        # Admin role can communicate either way
                        #_set_role(self, datapath, entry, role, port)
                        # from known device to new device
                        actions = [parser.OFPActionOutput(entry_port)]
                        match = parse.OFPMatch(in_port=port, eth_dst=entry_mac)
                        self.add_flow(dp, 1, match, actions)

                        # from new device to known device
                        actions = [parser.OFPActionOutput(port)]
                        match = parse.OFPMatch(in_port=entry_port, eth_dst=mac)
                        self.add_flow(dp, 1, match, actions)

    #def get_roles(self, dpid)


# Defines the URL to receive the HTTP request and its method
class SimpleSwitchController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(SimpleSwitchController, self).__init__(req, link, data, **config)
        self.simple_switch_app = data[simple_switch_instance_name]

    @route('simpleswitch', mac_url, methods=['GET'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def list_mac_table(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

        if dpid not in simple_switch.mac_to_port:
            return Response(status=404)

        mac_table = simple_switch.mac_to_port.get(dpid, {})

        body = json.dumps(mac_table)
        return Response(content_type='application/json', body=body)

    # Route to display the mac to role table
    @route('simpleswitch', role_url, methods=['GET'],
            requirements={'dpid': dpid_lib.DPID_PATTERN})
    def list_role_table(self, req, **kwargs):
        simple_switch = self.simple_switch_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

        if dpid not in simple_switch.mac_to_role:
            return Response(status=404)

        role_table = simple_switch.mac_to_role.get(dpid, {})

        body = json.dumps(role_table)
        return Response(content_type='application/json', body=body)

    @route('simpleswitch', mac_url, methods=['PUT'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def put_mac_table(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        if dpid not in simple_switch.mac_to_port:
            return Response(status=404)

        try:
            mac_table = simple_switch.set_mac_to_port(dpid, new_entry)
            body = json.dumps(mac_table)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(status=500)
