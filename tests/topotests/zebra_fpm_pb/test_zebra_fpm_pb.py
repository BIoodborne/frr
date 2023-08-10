#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
<template>.py: Test <template>.
"""

import os
import sys
import pytest
import json
import functools
# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import create_static_routes

NETWORK1_1 = {"ipv4": "1.1.1.1/32", "ipv6": "1::1/128"}
NETWORK1_2 = {"ipv4": "1.1.1.2/32", "ipv6": "1::2/128"}
NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}

def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    switch = tgen.add_switch('s1')
    switch.add_link(tgen.gears['r1'])
    switch.add_link(tgen.gears['r2'])

def setup_module(mod):
    "Sets up the pytest environment"
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r2", "r3"),
        "s3": ("r2", "r4"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        print(f"starting fpmsyncd for {rname}")
        router.startFpmSimulator()

        daemon_file = "{}/{}/zebra.conf".format(CWD, rname)
        router.load_config(TopoRouter.RD_ZEBRA, daemon_file,"-M dplane_fpm_pb")


        daemon_file = "{}/{}/bgpd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_BGP, daemon_file)


    # Initialize all routers.
    tgen.start_router()
    router1 = tgen.gears['r1']
    dir_path = f"{router1.logdir}/{router1.name}"
    json_path = f"{dir_path}/output.json"
    print(json_path)
    print("helloworld")

def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()

def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)

def check_rib(name,result_file, expected_file):
    def format_json_file(file):
        f=open(file,"r+")
        content=f.read()
        content=content.replace("}","},",content.count("}")-1)
        content="[\n"+content+"\n]"
        f.close()
        f=open(file,"w+")
        f.write(content)
        f.close()

    def _check(name,result_file, expected_file):
        logger.info("polling")

        tgen = get_topogen()
        router = tgen.gears[name]
        dir_path = f"{router.logdir}/{router.name}"
        json_path = f"{dir_path}/{result_file}"

        format_json_file(json_path)
        output = open_json_file(json_path)
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, result_file, expected_file))
    tgen = get_topogen()
    func = functools.partial(_check, name, result_file, expected_file)
    success, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
    assert result is None, "Failed"

def test_zebra_dplane_fpm_pb():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_rib("r1", "output.json", "r1/ref.json")
    
