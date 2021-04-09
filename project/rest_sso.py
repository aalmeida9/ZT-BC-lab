# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import requests
import logging
import json

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.exception import OFPUnknownVersion
from ryu.lib import mac
from ryu.lib import dpid as dpid_lib
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.lib.packet import packet
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser

from _sso import SSO, Match, Action


# =============================
#          REST API
# =============================
#
#  Note: specify switch and vlan group, as follows.
#   {switch-id} : 'all' or switchID
#   {vlan-id}   : 'all' or vlanID
#
#

# about SSO status
#
# get status of all SSO switches
# GET /SSO/module/status
#
# set enable the SSO switches
# PUT /SSO/module/enable/{switch-id}
#
# set disable the SSO switches
# PUT /SSO/module/disable/{switch-id}
#

# about SSO logs
#
# get log status of all SSO switches
# GET /SSO/log/status
#
# set log enable the SSO switches
# PUT /SSO/log/enable/{switch-id}
#
# set log disable the SSO switches
# PUT /SSO/log/disable/{switch-id}
#

# about SSO rules
#
# get rules of the SSO switches
# * for no vlan
# GET /SSO/rules/{switch-id}
#
# * for specific vlan group
# GET /SSO/rules/{switch-id}/{vlan-id}
#
#
# set a rule to the SSO switches
# * for no vlan
# POST /SSO/rules/{switch-id}
#
# * for specific vlan group
# POST /SSO/rules/{switch-id}/{vlan-id}
#
#  request body format:
#   {"<field1>":"<value1>", "<field2>":"<value2>",...}
#
#     <field>  : <value>
#    "priority": "0 to 65533"
#    "in_port" : "<int>"
#    "dl_src"  : "<xx:xx:xx:xx:xx:xx>"
#    "dl_dst"  : "<xx:xx:xx:xx:xx:xx>"
#    "dl_type" : "<ARP or IPv4 or IPv6>"
#    "nw_src"  : "<A.B.C.D/M>"
#    "nw_dst"  : "<A.B.C.D/M>"
#    "ipv6_src": "<xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/M>"
#    "ipv6_dst": "<xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/M>"
#    "nw_proto": "<TCP or UDP or ICMP or ICMPv6>"
#    "tp_src"  : "<int>"
#    "tp_dst"  : "<int>"
#    "actions" : "<ALLOW or DENY>"
#
#   Note: specifying nw_src/nw_dst
#         without specifying dl-type as "ARP" or "IPv4"
#         will automatically set dl-type as "IPv4".
#
#   Note: specifying ipv6_src/ipv6_dst
#         without specifying dl-type as "IPv6"
#         will automatically set dl-type as "IPv6".
#
#   Note: When "priority" has not been set up,
#         "0" is set to "priority".
#
#   Note: When "actions" has not been set up,
#         "ALLOW" is set to "actions".
#
#
# delete a rule of the SSO switches from ruleID
# * for no vlan
# DELETE /SSO/rules/{switch-id}
#
# * for specific vlan group
# DELETE /SSO/rules/{switch-id}/{vlan-id}
#
#  request body format:
#   {"<field>":"<value>"}
#
#     <field>  : <value>
#    "rule_id" : "<int>" or "all"
#


SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'
VLANID_PATTERN = r'[0-9]{1,4}|all'

REST_ALL = 'all'
REST_SWITCHID = 'switch_id'
REST_VLANID = 'vlan_id'
REST_RULE_ID = 'rule_id'
REST_STATUS = 'status'
REST_LOG_STATUS = 'log_status'
REST_STATUS_ENABLE = 'enable'
REST_STATUS_DISABLE = 'disable'
REST_COMMAND_RESULT = 'command_result'
REST_ACL = 'access_control_list'
REST_RULES = 'rules'
REST_COOKIE = 'cookie'
REST_PRIORITY = 'priority'
REST_MATCH = 'match'
REST_IN_PORT = 'in_port'
REST_SRC_MAC = 'dl_src'
REST_DST_MAC = 'dl_dst'
REST_DL_TYPE = 'dl_type'
REST_DL_TYPE_ARP = 'ARP'
REST_DL_TYPE_IPV4 = 'IPv4'
REST_DL_TYPE_IPV6 = 'IPv6'
REST_DL_VLAN = 'dl_vlan'
REST_SRC_IP = 'nw_src'
REST_DST_IP = 'nw_dst'
REST_SRC_IPV6 = 'ipv6_src'
REST_DST_IPV6 = 'ipv6_dst'
REST_NW_PROTO = 'nw_proto'
REST_NW_PROTO_TCP = 'TCP'
REST_NW_PROTO_UDP = 'UDP'
REST_NW_PROTO_ICMP = 'ICMP'
REST_NW_PROTO_ICMPV6 = 'ICMPv6'
REST_TP_SRC = 'tp_src'
REST_TP_DST = 'tp_dst'
REST_ACTION = 'actions'
REST_ACTION_ALLOW = 'ALLOW'
REST_ACTION_DENY = 'DENY'
REST_ACTION_PACKETIN = 'PACKETIN'


STATUS_FLOW_PRIORITY = ofproto_v1_3_parser.UINT16_MAX
ARP_FLOW_PRIORITY = ofproto_v1_3_parser.UINT16_MAX - 1
LOG_FLOW_PRIORITY = 0
ACL_FLOW_PRIORITY_MIN = LOG_FLOW_PRIORITY + 1
ACL_FLOW_PRIORITY_MAX = ofproto_v1_3_parser.UINT16_MAX - 2

VLANID_NONE = 0
VLANID_MIN = 2
VLANID_MAX = 4094
COOKIE_SHIFT_VLANID = 32


class SSO_API(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SSO_API, self).__init__(*args, **kwargs)

        # logger configure
        SSO_Controller.set_logger(self.logger)

        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters

        mapper = wsgi.mapper
        wsgi.registory['SSO_Controller'] = self.data
        path = '/SSO'
        requirements = {'switchid': SWITCHID_PATTERN,
                        'vlanid': VLANID_PATTERN}

        # for SSO roles
        uri = path + '/roles/{switchid}'
        mapper.connect('SSO', uri,
                        controller=SSO_Controller, action='set_role',
                        condition=dict(method=['POST']),
                        requirement=requirements)

        # for SSO status
        uri = path + '/module/status'
        mapper.connect('SSO', uri,
                       controller=SSO_Controller, action='get_status',
                       conditions=dict(method=['GET']))

        uri = path + '/module/enable/{switchid}'
        mapper.connect('SSO', uri,
                       controller=SSO_Controller, action='set_enable',
                       conditions=dict(method=['PUT']),
                       requirements=requirements)

        uri = path + '/module/disable/{switchid}'
        mapper.connect('SSO', uri,
                       controller=SSO_Controller, action='set_disable',
                       conditions=dict(method=['PUT']),
                       requirements=requirements)

        # for SSO logs
        uri = path + '/log/status'
        mapper.connect('SSO', uri,
                       controller=SSO_Controller, action='get_log_status',
                       conditions=dict(method=['GET']))

        uri = path + '/log/enable/{switchid}'
        mapper.connect('SSO', uri,
                       controller=SSO_Controller, action='set_log_enable',
                       conditions=dict(method=['PUT']),
                       requirements=requirements)

        uri = path + '/log/disable/{switchid}'
        mapper.connect('SSO', uri,
                       controller=SSO_Controller, action='set_log_disable',
                       conditions=dict(method=['PUT']),
                       requirements=requirements)

        # for no VLAN data
        uri = path + '/rules/{switchid}'
        mapper.connect('SSO', uri,
                       controller=SSO_Controller, action='get_rules',
                       conditions=dict(method=['GET']),
                       requirements=requirements)

        mapper.connect('SSO', uri,
                       controller=SSO_Controller, action='set_rule',
                       conditions=dict(method=['POST']),
                       requirements=requirements)

        mapper.connect('SSO', uri,
                       controller=SSO_Controller, action='delete_rule',
                       conditions=dict(method=['DELETE']),
                       requirements=requirements)

        # for VLAN data
        uri += '/{vlanid}'
        mapper.connect('SSO', uri, controller=SSO_Controller,
                       action='get_vlan_rules',
                       conditions=dict(method=['GET']),
                       requirements=requirements)

        mapper.connect('SSO', uri, controller=SSO_Controller,
                       action='set_vlan_rule',
                       conditions=dict(method=['POST']),
                       requirements=requirements)

        mapper.connect('SSO', uri, controller=SSO_Controller,
                       action='delete_vlan_rule',
                       conditions=dict(method=['DELETE']),
                       requirements=requirements)

    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION or \
                dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            SSO_Controller.regist_ofs(ev.dp)
        else:
            SSO_Controller.unregist_ofs(ev.dp)

    # for OpenFlow version1.0
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_0(self, ev):
        self.stats_reply_handler(ev)

    # for OpenFlow version1.2 or later
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        SSO_Controller.packet_in_handler(ev.msg)


class SSO_OfsList(dict):
    def __init__(self):
        super(SSO_OfsList, self).__init__()

    def get_ofs(self, dp_id):
        if len(self) == 0:
            raise ValueError('SSO sw is not connected.')

        dps = {}
        if dp_id == REST_ALL:
            dps = self
        else:
            try:
                dpid = dpid_lib.str_to_dpid(dp_id)
            except:
                raise ValueError('Invalid switchID.')

            if dpid in self:
                dps = {dpid: self[dpid]}
            else:
                msg = 'SSO sw is not connected. : switchID=%s' % dp_id
                raise ValueError(msg)

        return dps

# Roles that are accessed for configuring flow entries
# ip: role
role_table = {}
# List of server IPs filled when SSO is enabled
# make admins dict, ip: cert
admins = {}

class SSO_Controller(ControllerBase):

    _OFS_LIST = SSO_OfsList()
    _LOGGER = None

    def __init__(self, req, link, data, **config):
        super(SSO_Controller, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']

        #self.role_table = {}

    @classmethod
    def set_logger(cls, logger):
        cls._LOGGER = logger
        cls._LOGGER.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[FW][%(levelname)s] %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        cls._LOGGER.addHandler(hdlr)

    @staticmethod
    def regist_ofs(dp):
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        try:
            f_ofs = SSO(dp)
        except OFPUnknownVersion as message:
            SSO_Controller._LOGGER.info('dpid=%s: %s',
                                            dpid_str, message)
            return

        SSO_Controller._OFS_LIST.setdefault(dp.id, f_ofs)

        f_ofs.set_disable_flow()
        f_ofs.set_arp_flow()
        f_ofs.set_log_enable()
        SSO_Controller._LOGGER.info('dpid=%s: Join as SSO.',
                                        dpid_str)

    @staticmethod
    def unregist_ofs(dp):
        if dp.id in SSO_Controller._OFS_LIST:
            del SSO_Controller._OFS_LIST[dp.id]
            SSO_Controller._LOGGER.info('dpid=%s: Leave SSO.',
                                            dpid_lib.dpid_to_str(dp.id))

    # GET /SSO/roles/{switchid}

    # POST /SSO/roles/{switchid}
    # def set_role(self, req, switchid, **kwargs):
    #     return self._set_role(req, switchid)
    #
    # # GET /SSO/module/status
    # def get_status(self, req, **_kwargs):
    #     return self._access_module(REST_ALL, 'get_status',
    #                                waiters=self.waiters)

    # POST /SSO/module/enable/{switchid}
    def set_enable(self, req, switchid, **_kwargs):
        return self._access_module(switchid, 'set_enable_flow')

    # POST /SSO/module/disable/{switchid}
    def set_disable(self, req, switchid, **_kwargs):
        return self._access_module(switchid, 'set_disable_flow')

    # GET /SSO/log/status
    def get_log_status(self, dummy, **_kwargs):
        return self._access_module(REST_ALL, 'get_log_status',
                                   waiters=self.waiters)

    # PUT /SSO/log/enable/{switchid}
    def set_log_enable(self, dummy, switchid, **_kwargs):
        return self._access_module(switchid, 'set_log_enable',
                                   waiters=self.waiters)

    # PUT /SSO/log/disable/{switchid}
    def set_log_disable(self, dummy, switchid, **_kwargs):
        return self._access_module(switchid, 'set_log_disable',
                                   waiters=self.waiters)

    def _access_module(self, switchid, func, waiters=None):
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            function = getattr(f_ofs, func)
            msg = function() if waiters is None else function(waiters)
            msgs.append(msg)

        if(func == 'set_enable_flow'):
            roles = role_table

            # Get certificates from chain data
            req = requests.get("http://127.0.0.1:8000/chain",
                headers={'Content-type': 'application/json'})
            chain = req.json()
            blockchain = chain["chain"]

            # compare certifcate(s) in chain with cert from admin[chain ip]
            # Go through admins and connect them to other other roles
            for admin in admins.keys():
                # get admin certificate from bc
                certificate = {};
                for block in blockchain:
                    certificate = block["certificates"]
                    #Skip root certificate
                    if isinstance(certificate, str):
                        continue

                    if certificate["ip"] == admin:
                            print("match")
                            break;
                        # need to force match otherwise break

                #validate certificate for admins
                if certificate["cert"] != admins.get(admin):
                    print("certificates don't match for Admin".format(admin))
                    break;
                else:
                    print("certificates match for Admin {}".format(admin))

                # Configure flows between admins and other roles
                for ip, role in roles.items():
                    # avoid setting rules for the same src/dst
                    if admin != ip:
                        rule = {
                            'nw_src': admin,
                            'nw_dst': ip,
                            'nw_proto': 'ICMP',
                            'actions': 'ALLOW'
                        } # 'actions'
                        print("add flow: {}".format(rule))
                        f_ofs.set_rule(rule, self.waiters, VLANID_NONE)

                        rule = {
                            'nw_src': ip,
                            'nw_dst': admin,
                            'nw_proto': 'ICMP',
                            'actions': 'ALLOW'
                        } # 'actions'
                        print("add flow: {}".format(rule))
                        f_ofs.set_rule(rule, self.waiters, VLANID_NONE)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    # POST /SSO/rules/{switchid}
    def set_role(self, req, switchid, **_kwags):
        return self._set_role(req, switchid)

    # GET /SSO/rules/{switchid}
    def get_rules(self, req, switchid, **_kwargs):
        return self._get_rules(switchid)

    # GET /SSO/rules/{switchid}/{vlanid}
    def get_vlan_rules(self, req, switchid, vlanid, **_kwargs):
        return self._get_rules(switchid, vlan_id=vlanid)

    # POST /SSO/rules/{switchid}
    def set_rule(self, req, switchid, **_kwargs):
        #print("Test, req: {}".format(req))
        return self._set_rule(req, switchid)

    # POST /SSO/rules/{switchid}/{vlanid}
    def set_vlan_rule(self, req, switchid, vlanid, **_kwargs):
        return self._set_rule(req, switchid, vlan_id=vlanid)

    # DELETE /SSO/rules/{switchid}
    def delete_rule(self, req, switchid, **_kwargs):
        return self._delete_rule(req, switchid)

    # DELETE /SSO/rules/{switchid}/{vlanid}
    def delete_vlan_rule(self, req, switchid, vlanid, **_kwargs):
        return self._delete_rule(req, switchid, vlan_id=vlanid)

    #def _get_roles():

    # Funciton for setting roles, Worker: 0, Admin: 1, Server: 2
    # 0 to 1 and 1 to 0, 1 to 2 and 2 to 1
    def _set_role(self, req, switchid, vlanid=VLANID_NONE, **_kwargs):
        try:
            role_req = req.json if req.body else {}
        except ValueError:
            SSO_Controller._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)

        role_req = json.loads(role_req)
        role = role_req['role']
        src = role_req['nw_src']

        #roles = self.role_table.setdefault(switchid, {})
        role_table[src] = role
        if(role == 1):
            cert = role_req['cert']
            admins[src] = cert

        #body = json.dumps(role)
        #return Response(content_type='application/json', body=body)
        return "Success"

    def _get_rules(self, switchid, vlan_id=VLANID_NONE):
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
            vid = SSO_Controller._conv_toint_vlanid(vlan_id)
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            rules = f_ofs.get_rules(self.waiters, vid)
            msgs.append(rules)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    def _set_rule(self, req, switchid, vlan_id=VLANID_NONE):
        try:
            rule = req.json if req.body else {}
        except ValueError:
            SSO_Controller._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)

        try:
            dps = self._OFS_LIST.get_ofs(switchid)
            vid = SSO_Controller._conv_toint_vlanid(vlan_id)
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.set_rule(rule, self.waiters, vid)
                msgs.append(msg)
            except ValueError as message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    def _delete_rule(self, req, switchid, vlan_id=VLANID_NONE):
        try:
            ruleid = req.json if req.body else {}
        except ValueError:
            SSO_Controller._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)

        try:
            dps = self._OFS_LIST.get_ofs(switchid)
            vid = SSO_Controller._conv_toint_vlanid(vlan_id)
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.delete_rule(ruleid, self.waiters, vid)
                msgs.append(msg)
            except ValueError as message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    @staticmethod
    def _conv_toint_vlanid(vlan_id):
        if vlan_id != REST_ALL:
            vlan_id = int(vlan_id)
            if (vlan_id != VLANID_NONE and
                    (vlan_id < VLANID_MIN or VLANID_MAX < vlan_id)):
                msg = 'Invalid {vlan_id} value. Set [%d-%d]' % (VLANID_MIN,
                                                                VLANID_MAX)
                raise ValueError(msg)
        return vlan_id

    @staticmethod
    def packet_in_handler(msg):
        datapath = msg.datapath
        dpid = format(datapath.id, "d").zfill(16)

        pkt = packet.Packet(msg.data)

        # eth = pkt.get_protocols(ethernet.ethernet)[0]
        #
        # if eth.ethertype == ether_types.ETH_TYPE_LLDP:
        #     # ignore lldp packet
        #     return
        # dst = eth.dst
        # src = eth.src

        dpid_str = dpid_lib.dpid_to_str(msg.datapath.id)
        SSO_Controller._LOGGER.info('dpid=%s: Blocked packet = %s',
                                        dpid_str, pkt)
