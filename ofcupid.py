# Copyright (c) 2016 Richard Sanger
#
# Licensed under MIT

import copy
import glob
import json
import logging
import os
import pprint
import re
import signal
import sys
import traceback
import yaml

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3, ether
from webob import Response
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from collections import defaultdict

simple_switch_instance_name = 'simple_switch_api_app'

# Logging
log = logging.getLogger("patch_logger")
log.setLevel(logging.DEBUG)


def handleException(func):
    def handler(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except:
            log.critical(traceback.format_exc())
            log.critical("Args to %s:%s %s", func.__name__, args, kwargs)
            os._exit(-1)
    return handler

class DPID(object):
    def __init__(self, dpid):
        self.id = int(dpid)
        self.mappings = set()
        self.buckets = {}

    def __str__(self):
        return "DPID:{} links:<{}>".format(self.id,
                ', '.join([str(l) for l in self.mappings]))


class Link(object):
    def __init__(self, porta, portb):
        self.porta = min(porta, portb)
        self.portb = max(porta, portb)
        # False for bidirectional, or set to output port
        self.unidirectional = False

    def __str__(self):
        return "{}<->{}".format(self.porta, self.portb)

    def __hash__(self):
        return hash((self.porta, self.portb))

    def __eq__(self, other):
        if not isinstance(other, Link):
            return NotImplemented
        return (self.porta, self.portb, self.unidirectional) == (other.porta, other.portb, other.unidirectional)

    def __ne__(self, other):
        if not isinstance(other, Link):
            return NotImplemented
        return self != other


class Port(object):
    # VLAN 0xFFF means any VLAN
    # VLAN 0x000 means untagged traffic
    # VLAN -1 means both untagged and tagged traffic
    def __init__(self, number, vlan=-1):
        if isinstance(number, str) and '.' in number:
            _number, _vlan = number.split('.', 1)
            self.set_number(_number)
            self.set_vlan(_vlan)
        else:
            self.set_number(number)
            self.set_vlan(vlan)

    def get_number(self):
        return self._port_number

    def set_number(self, number):
        self._port_number = int(number)

    def get_vlan(self):
        return self._vlan_vid

    def set_vlan(self, vlan):
        self._vlan_vid = int(vlan)

    def serialized(self):
        if self.vlan >= 0:
            return "{}.{}".format(self.number, self.vlan)
        return str(self.number)

    number = property(get_number, set_number)
    vlan = property(get_vlan, set_vlan)

    def __str__(self):
        if self.vlan == 0xFFF:
            return "{}.*".format(self.number)
        elif self.vlan >= 0:
            return "{}.{}".format(self.number, self.vlan)
        return str(self.number)

    def __hash__(self):
        return hash((self.number, self.vlan))

    def __eq__(self, other):
        if not isinstance(other, Port):
            return NotImplemented
        return (self.number, self.vlan) == (other.number, other.vlan)

    def __ne__(self, other):
        if not isinstance(other, Port):
            return NotImplemented
        return self != other

    def __lt__(self, other):
        if not isinstance(other, Port):
            return NotImplemented
        return self.number < other.number

    def __le__(self, other):
        if not isinstance(other, Port):
            return NotImplemented
        return self.number <= other.number

    def __gt__(self, other):
        if not isinstance(other, Port):
            return NotImplemented
        return self.number > other.number

    def __ge__(self, other):
        if not isinstance(other, Port):
            return NotImplemented
        return self.number >= other.number


class PatchPanel(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication, 'dpset': dpset.DPSet}
    DROP_PRIORITY = 1000
    NORMAL_PRIORITY = 2000
    TAGGED_PRIORITY = 2500
    VLAN_PRIORITY = 3000
    COOKIE = 0x42
    datapaths = {}
    # Config [dpid][port] -> port name (or blocked) if blocked
    conf = {}
    s_names = {}
    log = log

    @handleException
    def __init__(self, *args, **kwargs):
        super(PatchPanel, self).__init__(*args, **kwargs)
        self.wsgi = kwargs['wsgi']
        self.wsgi.register(WebFace, {'main_app': self})
        self.dpset = kwargs['dpset']
        signal.signal(signal.SIGHUP, self.signal_handler)
        self.parse_config()
        self.create_saved_configs_dir()
        self.log.debug("Init Complete")

    def signal_handler(self, sigid, frame):
        if sigid == signal.SIGHUP:
            self.log.info("Caught SIGHUP, reloading configuration")
            self.datapaths = {}
            self.parse_config()
            self.create_saved_configs_dir()

    def expand_ranges(self, l):
        new = []
        if isinstance(l, list):
            pass
        elif isinstance(l, int):
            return [l]
        else:
            self.log.warning("Failed to parse config item %s", l)
            return []

        for i in l:
            if isinstance(i, int):
                new.append(i)
            elif isinstance(i, str):
                parsed = re.findall("(\d+)", i)
                if len(parsed) == 2:
                    new.extend(range(int(parsed[0]), int(parsed[1])+1))
                else:
                    self.log.warning("Failed to parse port range %s", i)
            else:
                self.log.warning("Removing invalid port range %s", i)
        return new

    @handleException
    def parse_config(self):
        """ Load the configuration file which includes which switches
            we will talk to and so on and friendly names
        """
        self.conf = {}

        conf_dirs = ['.', '/etc/ryu/ofcupid/']
        conf_file = None
        for conf_dir in conf_dirs:
            filename = os.path.join(conf_dir, "config.yaml")
            if os.path.exists(filename):
                conf_file = filename
                self.log.debug("Reading configuration from %s", conf_file)
                break
        if not conf_file:
            self.log.error("Couldn't find a configuration file in these directories: %s",
                           conf_dirs)
            sys.exit()

        with open(conf_file, 'r') as stream:
            conf = yaml.load(stream)
            for dpid, dconf in conf.items():
                # Convert any strings into sensible lists
                if not isinstance(dpid, str):
                    self.conf[dpid] = {}
                    if dconf is None:
                        continue
                    for name, ports in dconf.iteritems():
                        if name.lower() == 'name':
                            self.s_names[dpid] = str(ports)
                        else:
                            ports = self.expand_ranges(ports)
                            for port in ports:
                                self.conf[dpid][port] = name
                else:
                    self.conf[dpid] = copy.deepcopy(dconf)

        # Set some default config values
        self.conf.setdefault('saved_configs_dir', './configs/')

        self.log.debug("Loaded configuration:")
        self.log.debug(pprint.pformat(self.conf))

        # Reload connected switches, which will also clear non-managed switches
        for i, dp in self.dpset.get_all():
            self.reload_switch(dp)

    def create_saved_configs_dir(self):
        """ Create directory for saved configuration files if it doesn't exist """
        if os.path.exists(self.conf['saved_configs_dir']):
            return

        try:
            os.makedirs(self.conf['saved_configs_dir'])
        except Exception as e:
            self.log.error("Failed to create directory for saved configs %s, reason: %s",
                           self.conf['saved_configs_dir'], e)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                cookie=self.COOKIE)
        datapath.send_msg(mod)

    def add_group(self, datapath, group_id, buckets):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Try a OFPGC_ADD first, which should fail with an OFP_ERROR_MSG with
        # OFPET_GROUP_MOD_FAILED type and OFPMMFC_METER_EXISTS code if the group
        # already exists
        mod = parser.OFPGroupMod(datapath=datapath, command=ofproto.OFPGC_ADD,
                                 type_=ofproto.OFPGT_ALL, group_id=group_id,
                                 buckets=buckets)
        datapath.send_msg(mod)
        # Try a OFPGC_MODIFY for the case the group already exists
        mod = parser.OFPGroupMod(datapath=datapath, command=ofproto.OFPGC_MODIFY,
                                 type_=ofproto.OFPGT_ALL, group_id=group_id,
                                 buckets=buckets)
        datapath.send_msg(mod)

    def delete_group(self, datapath, group_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPGroupMod(command=ofproto.OFPGC_DELETE,
                                 datapath=datapath, type_=ofproto.OFPGT_ALL,
                                 group_id=group_id)
        datapath.send_msg(mod)

    def strict_del_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(command=ofproto.OFPFC_DELETE_STRICT,
                                datapath=datapath, priority=priority,
                                match=match, cookie=self.COOKIE,
                                cookie_mask=2**64-1,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)

    def reload_switch(self, dp):
        """ Called when a switch is first seen - or to reload rules
            If the switch is under our management we will reinstall the default
            drop and reload all associated flows.
            Otherwise we always attempt to delete any of our flows
        """
        if dp.id in self.conf:
            self.log.info("Installing switch %d", dp.id)
            self.datapaths[dp.id] = DPID(dp.id)
            parser = dp.ofproto_parser
            match = parser.OFPMatch()
            actions = []
            self.add_flow(dp, self.DROP_PRIORITY, match, actions)
            self.log.debug("Requesting groups from %d", dp.id)
            req = parser.OFPGroupDescStatsRequest(dp)
            dp.send_msg(req)
        else:
            self.log.info("Not using datapath %d, deleting our flows", dp.id)
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            mods = []
            mods.append(parser.OFPFlowMod(command=ofproto.OFPFC_DELETE,
                                          datapath=dp,
                                          cookie=self.COOKIE,
                                          cookie_mask=2**64-1,
                                          out_port=ofproto.OFPP_ANY,
                                          out_group=ofproto.OFPG_ANY))
            mods.append(parser.OFPGroupMod(command=ofproto.OFPGC_DELETE,
                                           datapath=dp, type_=ofproto.OFPGT_ALL,
                                           group_id=ofproto.OFPG_ALL))
            for mod in mods:
                dp.send_msg(mod)

    def reconfigure_switch(self, dp):
        if dp.id in self.conf:
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            mods = []
            mods.append(parser.OFPFlowMod(command=ofproto.OFPFC_DELETE,
                                          datapath=dp,
                                          cookie=self.COOKIE,
                                          cookie_mask=2**64-1,
                                          out_port=ofproto.OFPP_ANY,
                                          out_group=ofproto.OFPG_ANY))
            mods.append(parser.OFPGroupMod(command=ofproto.OFPGC_DELETE,
                                           datapath=dp, type_=ofproto.OFPGT_ALL,
                                           group_id=ofproto.OFPG_ALL))
            for mod in mods:
                dp.send_msg(mod)

            if dp.id in self.datapaths:
                for link in self.datapaths[dp.id].mappings:
                    self.install_single_link(self.datapaths[dp.id], link)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    @handleException
    def switch_enter_exit(self, ev):
        dp = ev.dp
        if not ev.enter:
            self.log.info("Switch exiting %d", dp.id)
            if dp.id in self.datapaths:
                del self.datapaths[dp.id]
            return
        self.log.info("Switch entering %d", dp.id)
        self.reload_switch(dp)

    @set_ev_cls(ofp_event.EventOFPGroupDescStatsReply, MAIN_DISPATCHER)
    @handleException
    def group_desc_stats_reply_handler(self, ev):
        parser = ev.msg.datapath.ofproto_parser
        dp = ev.msg.datapath
        self.log.debug("Received group description stats reply from %d", dp.id)
        for stat in ev.msg.body:
            self.datapaths[dp.id].buckets[stat.group_id] = stat.buckets
        self.log.debug("Requesting flows from %d", dp.id)
        req = parser.OFPFlowStatsRequest(
            dp, cookie=self.COOKIE, cookie_mask=2**64-1)
        dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    @handleException
    def flow_stats_reply_handler(self, ev):
        parser = ev.msg.datapath.ofproto_parser
        dp = ev.msg.datapath
        self.log.debug("Received flow stats reply from %d", dp.id)

        in_ports = {}

        flow_rules = [
            x for x in ev.msg.body
            if x.cookie == self.COOKIE
            and x.priority in [self.NORMAL_PRIORITY, self.TAGGED_PRIORITY,
                               self.VLAN_PRIORITY]
        ]

        for flow_rule in flow_rules:
            actions = next(
                (x.actions for x in flow_rule.instructions
                 if isinstance(x, parser.OFPInstructionActions))
            )
            group_actions = dict([
                (x.group_id, self.datapaths[dp.id].buckets[x.group_id])
                for x in actions
                if isinstance(x, parser.OFPActionGroup)
            ])
            vlan_vid = -1
            if 'vlan_vid' in flow_rule.match:
                if (isinstance(flow_rule.match['vlan_vid'], tuple) and
                        flow_rule.match['vlan_vid'] == (ofproto_v1_3.OFPVID_PRESENT,
                                                        ofproto_v1_3.OFPVID_PRESENT)):
                    vlan_vid = 0xFFF
                elif flow_rule.match['vlan_vid'] == ofproto_v1_3.OFPVID_NONE:
                    vlan_vid = 0
                else:
                    vlan_vid = flow_rule.match['vlan_vid'] ^ ofproto_v1_3.OFPVID_PRESENT
            full_in_port = "%s.%s" % (flow_rule.match['in_port'], vlan_vid)
            in_ports[full_in_port] = []
            for group_id, buckets in group_actions.iteritems():
                for bucket in buckets:
                    output = next(
                        (x.port for x in bucket.actions
                         if isinstance(x, parser.OFPActionOutput)), None
                    )
                    set_vlan_vid = next(
                        (x.value ^ ofproto_v1_3.OFPVID_PRESENT
                         for x in bucket.actions
                         if isinstance(x, parser.OFPActionSetField)
                         and x.key == "vlan_vid"), -1
                    )
                    pop_vlan = next(
                        (x for x in bucket.actions
                         if isinstance(x, parser.OFPActionPopVlan)), None
                    )
                    if vlan_vid > 0:
                        if pop_vlan:
                            # VLAN -> Native
                            full_output = "%s.%s" % (output, set_vlan_vid)
                        elif set_vlan_vid > 0:
                            # VLAN -> VLAN (rewritten)
                            full_output = "%s.%s" % (output, set_vlan_vid)
                        else:
                            # VLAN -> VLAN
                            full_output = "%s.%s" % (output, vlan_vid)
                    else:
                        # Native -> VLAN
                        # Native -> Native
                        full_output = "%s.%s" % (output, set_vlan_vid)
                    in_ports[full_in_port].append(full_output)

        # Make our links
        for in_port, outputs in in_ports.iteritems():
            # If both directions exist add a link
            for output in outputs:
                if output in in_ports:
                    link = Link(Port(in_port), Port(output))
                    self.log.debug("Adding link %s to %s", link, self.datapaths[dp.id])
                    self.datapaths[dp.id].mappings.add(link)

        default_conf_file = "default_" + str(dp.id)
        default_conf_path = self.validate_path(self.conf['saved_configs_dir'],
                                               default_conf_file)
        if os.path.isfile(default_conf_path + ".yaml"):
            self.log.debug("Loading default configuration for %s from %s",
                           dp.id, default_conf_file)
            self.load_conf(default_conf_file, False, "replace", dp.id)

        self.print_connections()

    def print_connections(self):
        for dpid, dp in self.datapaths.iteritems():
            self.log.debug(dp)

    def get_friendly(self, dpid, port):
        proto = self.dpset.get(dpid).ofproto
        if port > proto.OFPP_MAX:
            return False
        if dpid in self.conf:
            if port in self.conf[dpid]:
                if self.conf[dpid][port].lower() == 'blocked':
                    return False
                else:
                    return self.conf[dpid][port]
        try:
            data = self.dpset.get_port(dpid, port)
            return data.name
        except:
            pass
        return None

    def make_friendly(self, result):
        """ Add a friendly name to a result both port
            and dpid"""
        if 'dpid' in result:
            self.name_dpid(result)
        if 'port' in result:
            result['port_name'] = self.get_friendly(int(result['dpid']),
                                                    result['port'])
        return result

    def get_friendlys(self, dpid, ports):
        return [self.make_friendly({'port': p, 'dpid': str(dpid)})
                for p in ports if self.get_friendly(dpid, p)]

    def name_dpid(self, dpid):
        try:
            dpid['dpid_name'] = self.s_names[int(dpid['dpid'])]
        except:
            dpid['dpid_name'] = str(dpid['dpid'])
        return dpid

    def get_switches(self):
        """ Returns all switches currently managed, as id, name dict.
            Note the id is a string to avoid complications with javascript
            and large numbers
        """
        switches = [{'dpid': str(x[0])} for x in self.dpset.get_all()
                    if x[0] in self.conf]
        for switch in switches:
            self.name_dpid(switch)
        return switches

    def get_connections(self, dpid):
        links = []
        dpids = self.parse_dpids(dpid)
        for dpid in dpids:
            dp = self.datapaths[dpid]
            for link in dp.mappings:
                porta = self.make_friendly({
                    'port': link.porta.number,
                    'vlan': link.porta.vlan,
                    'dpid': str(dp.id)
                })
                portb = self.make_friendly({
                    'port': link.portb.number,
                    'vlan': link.portb.vlan,
                    'dpid': str(dp.id)
                })
                links.extend([
                    {'dpid': str(dp.id), 'src': porta, 'dst': portb},
                    {'dpid': str(dp.id), 'src': portb, 'dst': porta}
                ])
        return links

    def install_single_link(self, dp, link):
        # Install link in both directions
        for in_port in [link.porta, link.portb]:
            self.install_port_rule(dp, in_port)

    def remove_single_link(self, dp, link):
        # Remove link in both directions
        for in_port in [link.porta, link.portb]:
            self.remove_port_rule(dp, in_port)

    def install_port_rule(self, dp, port):
        # Generates a group per port, each group contains a number of buckets
        # for performing the correct action for each output port.
        parser = self.dpset.get(dp.id).ofproto_parser
        actions = []
        buckets = []

        if port.vlan > 0:
            if port.vlan == 0xFFF:
                vlan_match = (ofproto_v1_3.OFPVID_PRESENT,
                              ofproto_v1_3.OFPVID_PRESENT)
                priority = self.TAGGED_PRIORITY
            else:
                vlan_match = port.vlan|ofproto_v1_3.OFPVID_PRESENT
                priority = self.VLAN_PRIORITY

            match = parser.OFPMatch(in_port=port.number,
                                    vlan_vid=vlan_match)

            # VLAN -> Native, VLAN -> Untagged, Tagged -> Native, Tagged -> Untagged
            buckets.extend([
                parser.OFPBucket(actions=[
                    parser.OFPActionPopVlan(),
                    parser.OFPActionOutput(l.portb.number)
                ])
                for l in dp.mappings
                if l.porta.number == port.number
                and l.porta.vlan == port.vlan
                and (l.portb.vlan == -1 or l.portb.vlan == 0)
            ])
            buckets.extend([
                parser.OFPBucket(actions=[
                    parser.OFPActionPopVlan(),
                    parser.OFPActionOutput(l.porta.number)
                ])
                for l in dp.mappings
                if l.portb.number == port.number
                and l.portb.vlan == port.vlan
                and (l.porta.vlan == -1 or l.porta.vlan == 0)
            ])

            # VLAN -> VLAN, Tagged -> Tagged
            buckets.extend([
                parser.OFPBucket(actions=[
                    parser.OFPActionOutput(l.portb.number)
                ])
                for l in dp.mappings
                if l.porta.number == port.number
                and l.portb.vlan == port.vlan
            ])
            buckets.extend([
                parser.OFPBucket(actions=[
                    parser.OFPActionOutput(l.porta.number)
                ])
                for l in dp.mappings
                if l.portb.number == port.number
                and l.porta.vlan == port.vlan
            ])

            # VLAN -> VLAN (rewritten), Tagged -> VLAN
            buckets.extend([
                parser.OFPBucket(actions=[
                    parser.OFPActionSetField(vlan_vid=l.portb.vlan|ofproto_v1_3.OFPVID_PRESENT),
                    parser.OFPActionOutput(l.portb.number)
                ])
                for l in dp.mappings
                if l.porta.number == port.number
                and l.portb.vlan > 0
                and l.portb.vlan < 0xFFF
                and l.portb.vlan != port.vlan
            ])
            buckets.extend([
                parser.OFPBucket(actions=[
                    parser.OFPActionSetField(vlan_vid=l.porta.vlan|ofproto_v1_3.OFPVID_PRESENT),
                    parser.OFPActionOutput(l.porta.number)
                ])
                for l in dp.mappings
                if l.portb.number == port.number
                and l.porta.vlan > 0
                and l.porta.vlan < 0xFFF
                and l.porta.vlan != port.vlan
            ])
            # !!! Not Handled: VLAN -> Tagged !!!
        else:
            if port.vlan == 0:
                vlan_match = ofproto_v1_3.OFPVID_NONE
                match = parser.OFPMatch(in_port=port.number, vlan_vid=vlan_match)
                priority = self.TAGGED_PRIORITY
            else:
                match = parser.OFPMatch(in_port=port.number)
                priority = self.NORMAL_PRIORITY

            # Native -> Native, Native -> Untagged, Untagged -> Native, Untagged -> Native
            buckets.extend([
                parser.OFPBucket(actions=[
                    parser.OFPActionOutput(l.portb.number)
                ])
                for l in dp.mappings
                if l.porta.number == port.number
                and l.porta.vlan == port.vlan
                and (l.portb.vlan == -1 or l.portb.vlan == 0)
            ])
            buckets.extend([
                parser.OFPBucket(actions=[parser.OFPActionOutput(l.porta.number)])
                for l in dp.mappings
                if l.portb.number == port.number
                and l.portb.vlan == port.vlan
                and (l.porta.vlan == -1 or l.porta.vlan == 0)
            ])

            # Native -> VLAN, Untagged -> VLAN
            buckets.extend([
                parser.OFPBucket(actions=[
                    parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
                    parser.OFPActionSetField(vlan_vid=l.portb.vlan|ofproto_v1_3.OFPVID_PRESENT),
                    parser.OFPActionOutput(l.portb.number)
                ])
                for l in dp.mappings
                if l.porta.number == port.number
                and l.portb.vlan > 0
                and l.portb.vlan < 0xFFF
            ])
            buckets.extend([
                parser.OFPBucket(actions=[
                    parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
                    parser.OFPActionSetField(vlan_vid=l.porta.vlan|ofproto_v1_3.OFPVID_PRESENT),
                    parser.OFPActionOutput(l.porta.number)
                ])
                for l in dp.mappings
                if l.portb.number == port.number
                and l.porta.vlan > 0
                and l.porta.vlan < 0xFFF
            ])
            # !!! Not handled: Native -> Tagged,  Untagged -> Tagged !!!

        actions = [parser.OFPActionGroup(port.number)]

        self.add_group(self.dpset.get(dp.id), port.number, buckets)
        self.add_flow(self.dpset.get(dp.id), priority, match, actions)

    def remove_port_rule(self, dp, port):
        parser = self.dpset.get(dp.id).ofproto_parser
        match = parser.OFPMatch(in_port=port.number)
        self.strict_del_flow(self.dpset.get(dp.id), self.NORMAL_PRIORITY, match)
        self.delete_group(self.dpset.get(dp.id), port.number)

    def validate_dpid(self, dpid):
        return dpid in self.conf and self.dpset.get(dpid) is not None

    def parse_dpid(self, dpid):
        dpid = int(dpid)
        if self.validate_dpid(dpid):
            return dpid
        else:
            raise Exception("Invalid Switch Selected")

    def parse_dpids(self, dpid=""):
        dpids = []
        if dpid == "" or dpid is None:
            dpids = [x[0] for x in self.dpset.get_all()]
        elif isinstance(dpid, set):
            dpids = dpid
        else:
            try:
                dpids = [self.parse_dpid(dpid)]
            except:
                pass
        return [x for x in dpids if self.validate_dpid(x)]

    def get_ports(self, dpid="", datapaths=None):
        if not datapaths:
            datapaths = self.datapaths
        dpids = self.parse_dpids(dpid)
        all_ports = []
        for dpid in dpids:
            dp = datapaths[dpid]
            proto = self.dpset.get(dp.id).ofproto
            ports = self.dpset.get_ports(dp.id)
            ports = [x.port_no for x in ports if (x.state == 0
                     or x.state == proto.OFPPS_LINK_DOWN) and x.config == 0]
            ports = self.get_friendlys(dpid, ports)
            for port in ports:
                port['links'] = []
                port['links'].extend([
                    str(l.portb)
                    for l in dp.mappings
                    if l.porta.number == port['port']
                ])
                port['links'].extend([
                    str(l.porta)
                    for l in dp.mappings
                    if l.portb.number == port['port']
                ])
                port['curr_speed'] = self.dpset.get_port(dp.id, port['port']).curr_speed
            all_ports.extend(ports)
        return all_ports

    def add_link(self, dpid, link):
        dp = self.datapaths[self.parse_dpid(dpid)]
        self.log.debug("Adding link %s to %s", link, dp)
        if link not in dp.mappings:
            dp.mappings.add(link)
            self.install_single_link(dp, link)
        else:
            self.log.error("Link %s is already present in %s", link, dp)

    def remove_link(self, dpid, link):
        dp = self.datapaths[self.parse_dpid(dpid)]
        self.log.debug("Removing link %s from %s", link, dp)
        if link in dp.mappings:
            self.remove_single_link(dp, link)
            dp.mappings.remove(link)
        else:
            self.log.error("Link %s is not in %s", link, dp)

    def remove_port(self, dpid, port):
        dp = self.datapaths[self.parse_dpid(dpid)]
        # Remove all references to a particular port
        self.log.debug("Removing port %s from %s", port, dp)
        self.remove_port_rule(dp, Port(port))

        # Do opposite - NOP if we do nothing
        links = [
            l for l in dp.mappings
            if l.porta.number == port
            or l.portb.number == port
        ]
        for link in links:
            self.log.debug("Removing link %s from %s", link, dp)
            self.remove_single_link(dp, link)
            dp.mappings.remove(link)
        return True

    def get_configs(self):
        configs = glob.glob(self.conf['saved_configs_dir'] + "/*.yaml")
        configs = [c.split("/")[-1][0:-5] for c in configs]
        return configs

    def emulate_conf(self, config, merge="replace", dpid=""):
        if merge == "replace":
            emulated_datapaths = {}
            for dpid, ports in config.iteritems():
                datapath = DPID(dpid)
                for src, dests in ports.iteritems():
                    src_port = Port(src)
                    for dst in dests:
                        dst_port = Port(dst)
                        datapath.mappings.add(Link(src_port, dst_port))
                emulated_datapaths[dpid] = datapath
        elif merge == "merge":
            emulated_datapaths = copy.deepcopy(self.datapaths)
            for dpid, ports in config.iteritems():
                for src, dests in ports.iteritems():
                    src_port = Port(src)
                    for dst in dests:
                        dst_port = Port(dst)
                        emulated_datapaths[dpid].mappings.add(Link(src_port, dst_port))
        elif merge == "merge_exclusive":
            emulated_datapaths = copy.deepcopy(self.datapaths)
            for dpid, ports in config.iteritems():
                for src, dests in ports.iteritems():
                    src_port = Port(src)
                    links = [
                        l for l in emulated_datapaths[dpid].mappings
                        if l.porta.number == src_port.number
                        or l.portb.number == src_port.number
                    ]
                    for link in links:
                        emulated_datapaths[dpid].mappings.remove(link)
                    for dst in dests:
                        dst_port = Port(dst)
                        emulated_datapaths[dpid].mappings.add(Link(src_port, dst_port))

        return emulated_datapaths

    def validate_path(self, base, name):
        path = os.path.join(base, name)
        path = os.path.abspath(path)
        if os.path.abspath(base) == os.path.dirname(path):
            return path
        raise ValueError("Invalid Path")

    def load_conf(self, name, simulate, merge="replace", dpid=""):
        name = self.validate_path(self.conf['saved_configs_dir'], name + ".yaml")
        with open(name, 'r') as stream:
            conf = yaml.load(stream)
            new = self.emulate_conf(conf, merge, dpid)
            if simulate:
                return self.get_ports(dpid=dpid, datapaths=new)
            else:
                self.datapaths = new
                for i, dp in self.dpset.get_all():
                    self.reconfigure_switch(dp)
                return self.get_ports()

    def save_conf(self, name):
        name = self.validate_path(self.conf['saved_configs_dir'], name + ".yaml")
        data = {}
        for dpid, dp in self.datapaths.iteritems():
            data[dp.id] = {}
            for link in dp.mappings:
                data[dp.id].setdefault(link.porta.serialized(), set())
                data[dp.id].setdefault(link.portb.serialized(), set())
                data[dp.id][link.porta.serialized()].add(link.portb.serialized())
                data[dp.id][link.portb.serialized()].add(link.porta.serialized())
            for port, outputs in data[dp.id].iteritems():
                data[dp.id][port] = list(outputs)
        self.log.debug(data)

        with open(name, 'w') as stream:
            stream.write(yaml.dump(data, default_flow_style=False))


class WebFace(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(WebFace, self).__init__(req, link, data, **config)
        self.app = data['main_app']

    @route('patch', "/api/current_mappings", methods=['POST'])
    def get_connection(self, req, **kwargs):
        args = {}
        if req.body:
            args = json.loads(req.body)
        try:
            return Response(content_type='application/json',
                            body=json.dumps(self.app.get_connections(**args)))
        except:
            return Response(status=500, body=traceback.format_exc())

    @route('patch', "/api/ports", methods=['POST'])
    def get_ports(self, req, **kwargs):
        if req.body:
            args = json.loads(req.body)
        try:
            return Response(content_type='application/json',
                            body=json.dumps(self.app.get_ports(**args)))
        except:
            return Response(status=500, body=traceback.format_exc())

    @route('patch', "/api/link", methods=['PUT'])
    def do_link(self, req, **kwargs):
        args = {}
        if req.body:
            args = json.loads(req.body)
        try:
            porta = Port(args['porta'])
            portb = Port(args['portb'])
            # Add VLAN tag information if we have it
            if 'porta.vlan_vid' in args and isinstance(args['porta.vlan_vid'], int):
                porta.vlan = args['porta.vlan_vid']
            if 'portb.vlan_vid' in args and isinstance(args['portb.vlan_vid'], int):
                portb.vlan = args['portb.vlan_vid']
            link = Link(porta, portb)
            self.app.add_link(args['dpid'], link)
            return Response(content_type='application/json',
                            body=json.dumps(True))
        except:
            return Response(status=500, body=traceback.format_exc())

    @route('patch', "/api/unlink_port", methods=['PUT'])
    def unlink_port(self, req, **kwargs):
        args = {}
        if req.body:
            args = json.loads(req.body)
        try:
            self.app.remove_port(**args)
            return Response(content_type='application/json',
                            body=json.dumps(True))
        except:
            return Response(status=500, body=traceback.format_exc())

    @route('patch', "/api/unlink", methods=['PUT'])
    def unlink(self, req, **kwargs):
        args = {}
        if req.body:
            args = json.loads(req.body)
        try:
            porta = Port(args['porta'])
            portb = Port(args['portb'])
            # Add VLAN tag information if we have it
            if 'porta.vlan_vid' in args and isinstance(args['porta.vlan_vid'], int):
                porta.vlan = args['porta.vlan_vid']
            if 'portb.vlan_vid' in args and isinstance(args['portb.vlan_vid'], int):
                portb.vlan = args['portb.vlan_vid']
            link = Link(porta, portb)
            self.app.remove_link(args['dpid'], link)
            return Response(content_type='application/json',
                            body=json.dumps(True))
        except:
            return Response(status=500, body=traceback.format_exc())

    @route('patch', "/api/configs", methods=['POST'])
    def get_configs(self, req, **kwargs):
        try:
            return Response(content_type='application/json',
                            body=json.dumps(self.app.get_configs()))
        except:
            return Response(status=500, body=traceback.format_exc())

    @route('patch', "/api/load_conf", methods=['PUT'])
    def load_conf(self, req, **kwargs):
        args = {}
        if req.body:
            args = json.loads(req.body)
        try:
            return Response(content_type='application/json',
                            body=json.dumps(self.app.load_conf(**args)))
        except:
            return Response(status=500, body=traceback.format_exc())

    @route('patch', "/api/save_conf", methods=['PUT'])
    def save_conf(self, req, **kwargs):
        args = {}
        if req.body:
            args = json.loads(req.body)
        if 'name' in args:
            return Response(content_type='application/json',
                            body=json.dumps(self.app.save_conf(args['name'])))
        else:
            return Response(status=500)

    @route('patch', "/api/switches", methods=['GET'])
    def get_switches(self, req, **kwargs):
        return Response(content_type='application/x-javascript',
                        body=json.dumps(self.app.get_switches()))

    # Static page content
    @route('patch', "/", methods=['GET'])
    def get_page(self, req, **kwargs):
        with open('ofcupid.html', 'r') as f:
            return Response(content_type='text/html', body=f.read())

    @route('patch', "/ofcupid.css", methods=['GET'])
    def get_css(self, req, **kwargs):
        with open('ofcupid.css', 'r') as f:
            return Response(content_type='text/css', body=f.read())

    @route('patch', "/third_party/angular.min.js", methods=['GET'])
    def get_angular(self, req, **kwargs):
        with open('third_party/angular.min.js', 'r') as f:
            return Response(content_type='application/x-javascript',
                            body=f.read())

    @route('patch', "/third_party/bootstrap.min.css", methods=['GET'])
    def get_bootstrap(self, req, **kwargs):
        with open('third_party/bootstrap.min.css', 'r') as f:
            return Response(content_type='text/css', body=f.read())

    @route('patch', "/ofcupid.js", methods=['GET'])
    def get_js(self, req, **kwargs):
        with open('ofcupid.js', 'r') as f:
            return Response(content_type='application/x-javascript',
                            body=f.read())
