# Copyright (c) 2016 Richard Sanger
#
# Licensed under MIT

import json
import logging
import signal
import copy
import yaml
import re
import glob
import os
import sys
import traceback

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
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


class PatchPanel(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication, 'dpset': dpset.DPSet}
    DROP_PRIORITY = 1000
    NORMAL_PRIORITY = 2000
    COOKIE = 0x42
    # Mappings [dpid][port_in] to [port_out(s)], else drop
    mappings = defaultdict(lambda: defaultdict(set))
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
            self.mappings = defaultdict(lambda: defaultdict(set))
            self.parse_config()
            self.create_saved_configs_dir()

    def expand_ranges(self, l):
        new = []
        if type(l) is list:
            pass
        elif type(l) is int:
            return [l]
        else:
            self.log.warning("Failed to parse config item %s", l)
            return []

        for i in l:
            if type(i) is int:
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
                if type(dpid) is int:
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

        self.log.debug("Loaded configuration: %s", self.conf)

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
            parser = dp.ofproto_parser
            match = parser.OFPMatch()
            actions = []
            self.add_flow(dp, self.DROP_PRIORITY, match, actions)
            # Get all the things
            match = parser.OFPMatch()
            req = parser.OFPFlowStatsRequest(
                dp, cookie=self.COOKIE, cookie_mask=2**64-1)
            dp.send_msg(req)
            self.log.debug("Requesting flows from %d", dp.id)
        else:
            self.log.info("Not using datapath %d, deleting our flows", dp.id)
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            mod = parser.OFPFlowMod(command=ofproto.OFPFC_DELETE,
                                    datapath=dp,
                                    cookie=self.COOKIE,
                                    cookie_mask=2**64-1,
                                    out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY)
            dp.send_msg(mod)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    @handleException
    def switch_enter_exit(self, ev):
        dp = ev.dp
        if not ev.enter:
            self.log.info("Switch exiting: %d", dp.id)
            if dp.id in self.mappings:
                del self.mappings[dp.id]
            return
        self.log.info("Switch entering: %d", dp.id)
        self.reload_switch(dp)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    @handleException
    def flow_stats_reply_handler(self, ev):
        parser = ev.msg.datapath.ofproto_parser
        dpid = ev.msg.datapath.id
        self.log.debug("Received stats reply from %d", dpid)
        for stat in ev.msg.body:
            if ('in_port' in stat.match and
               stat.priority == self.NORMAL_PRIORITY):
                for actions in [x for x in stat.instructions
                                if isinstance(x, parser.OFPInstructionActions)]:
                    for action in [x for x in actions.actions
                                   if isinstance(x, parser.OFPActionOutput)]:
                        self.mappings[dpid][stat.match['in_port']].add(
                            action.port)
        self.print_connections()
        self.verify_connections()

    def print_connections(self):
        for dpid, in_ports in self.mappings.iteritems():
            self.log.debug("%d:", dpid)
            for in_port, out_ports in in_ports.iteritems():
                for out_port in out_ports:
                    self.log.debug("\t %d -> %d", in_port, out_port)

    def verify_connections(self):
        good = True
        for dpid, in_ports in self.mappings.iteritems():
            for in_port, out_ports in in_ports.iteritems():
                for out_port in out_ports:
                    # Ensure we don't accidently add an extra item by default
                    if (out_port not in self.mappings[dpid] or in_port
                       not in self.mappings[dpid][out_port]):
                        self.log.warning(
                            "Error single direction mapping for %d -> %d",
                            in_port, out_port)
                        good = False
        return good

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

    def get_connections(self, dpid, port=None, mappings=None):
        if not mappings:
            mappings = self.mappings
        l = []
        dpids = self.parse_dpids(dpid)
        for dpid in dpids:
            for in_port, out_ports in mappings[dpid].iteritems():
                if port and in_port != port:
                    continue
                k = self.make_friendly({'port': in_port, 'dpid': str(dpid)})
                vs = self.get_friendlys(dpid, out_ports)
                res = [{'dpid': str(dpid), 'src': k, 'dst': x} for x in vs]
                if len(res):
                    l.extend(res)
        return l

    def install_single_link(self, dpid, in_port, out_port, add):
        orig_len = len(self.mappings[dpid][in_port])
        if add:
            self.mappings[dpid][in_port].add(out_port)
        else:
            self.mappings[dpid][in_port].discard(out_port)
        if orig_len != len(self.mappings[dpid][in_port]):
            self.install_port(dpid, in_port)
            return True
        return False

    def install_port(self, dpid, port):
        parser = self.dpset.get(dpid).ofproto_parser
        match = parser.OFPMatch(in_port=port)
        actions = [parser.OFPActionOutput(p) for p in self.mappings[dpid][port]]
        if len(actions):
            self.add_flow(self.dpset.get(dpid), self.NORMAL_PRIORITY,
                          match, actions)
        else:
            self.strict_del_flow(self.dpset.get(dpid), self.NORMAL_PRIORITY,
                                 match)

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
        elif type(dpid) is set:
            dpids = dpid
        else:
            try:
                dpids = [self.parse_dpid(dpid)]
            except:
                pass
        return [x for x in dpids if self.validate_dpid(x)]

    def get_ports(self, dpid="", mappings=None):
        if not mappings:
            mappings = self.mappings
        dpids = self.parse_dpids(dpid)
        all_ports = []
        for dpid in dpids:
            proto = self.dpset.get(dpid).ofproto
            ports = self.dpset.get_ports(dpid)
            ports = [x.port_no for x in ports if (x.state == 0
                     or x.state == proto.OFPPS_LINK_DOWN) and x.config == 0]
            ports = self.get_friendlys(dpid, ports)
            for port in ports:
                port['links'] = list(mappings[dpid][port['port']])
                port['curr_speed'] = self.dpset.get_port(dpid, port['port']).curr_speed
            all_ports.extend(ports)
        return all_ports

    def add_link(self, dpid, portA, portB):
        dpid = self.parse_dpid(dpid)
        self.install_single_link(dpid, portA, portB, True)
        self.install_single_link(dpid, portB, portA, True)

    def remove_link(self, dpid, portA, portB):
        dpid = self.parse_dpid(dpid)
        self.install_single_link(dpid, portA, portB, False)
        self.install_single_link(dpid, portB, portA, False)

    def remove_port(self, dpid, port):
        dpid = self.parse_dpid(dpid)
        # Remove all references to a particular port
        if len(self.mappings[dpid][port]):
            # Add one then remove it, this will install a drop rule
            self.mappings[dpid][port] = set([1])
            self.install_single_link(dpid, port, 1, False)

        # Do opposite - NOP if we do nothing
        for in_port in self.mappings[dpid]:
            self.install_single_link(dpid, in_port, port, False)
        return True

    def get_configs(self):
        configs = glob.glob(self.conf['saved_configs_dir'] + "/*.yaml")
        configs = [c.split("/")[-1][0:-5] for c in configs]
        return configs

    def emulate_conf(self, yaml, merge="replace_all", dpid=""):
        dpids = self.parse_dpids(dpid)
        if merge == "replace_all":
            nconf = defaultdict(lambda: defaultdict(set))
            for dpid, data in self.mappings.iteritems():
                if dpid not in dpids:
                    nconf[dpid] = copy.deepcopy(self.mappings[dpid])
        elif merge == "combine":
            nconf = copy.deepcopy(self.mappings)
        elif merge == "replace_ports":
            nconf = copy.deepcopy(self.mappings)
            for dpid, dconf in yaml.items():
                if dpid in dpids:
                    for l, r in dconf.iteritems():
                        for i in nconf[dpid][l]:
                            nconf[dpid][i].discard(l)
                        del nconf[dpid][l]

        for dpid, dconf in yaml.items():
            if dpid in dpids:
                for l, r in dconf.iteritems():
                    nconf[dpid][l].update(self.expand_ranges(r))
        return nconf

    def swap_mappings(self, new):
        """ Swap the existing mappings with a new set """
        for dpid, conf in self.mappings.iteritems():
            for port, ports in conf.iteritems():
                if new[dpid][port] != ports:
                    ports.clear()
                    ports.update(new[dpid][port])
                    self.install_port(dpid, port)

    def validate_path(self, base, name):
        path = os.path.join(base, name)
        path = os.path.abspath(path)
        if os.path.abspath(base) == os.path.dirname(path):
            return path
        raise ValueError("Invalid Path")

    def load_conf(self, name, simulate, merge="replace_all", dpid=""):
        name = self.validate_path(self.conf['saved_configs_dir'], name + ".yaml")
        with open(name, 'r') as stream:
            conf = yaml.load(stream)
            new = self.emulate_conf(conf, merge, dpid)
            if simulate:
                return self.get_ports(dpid=dpid, mappings=new)
            else:
                self.swap_mappings(new)
                return self.get_ports()

    def save_conf(self, name):
        name = self.validate_path(self.conf['saved_configs_dir'], name + ".yaml")
        data = {}
        print self.mappings
        for dpid, dconf in self.mappings.iteritems():
            data[dpid] = {}
            for l, r in dconf.iteritems():
                if len(r):
                    data[dpid][l] = list(r)

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
            args['dpid'] = int(args['dpid'])
            self.app.add_link(**args)
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
            self.app.remove_link(**args)
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
