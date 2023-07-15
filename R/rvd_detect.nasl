#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#



include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(21676);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Rendezvous Daemon Detection");

  script_set_attribute(attribute:"synopsis", value:
"There is a Rendezvous daemon listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Rendezvous daemon on the specified port. 
Rendezvous is a commercial messaging software product used for
building distributed applications, and a Rendezvous daemon is the
central communications component of the software.");
  script_set_attribute(attribute:"see_also", value:"https://www.tibco.com/products/tibco-rendezvous");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tibco:rendezvous");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 7500);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(7500);
  if (!port) exit(0);
}
else port = 7500;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Make sure the banner looks like it's from rvd.
res = recv(socket:soc, length:512, min:12);
pkt1 = 
  mkdword(0) + mkdword(4) + 
  mkdword(0);
if (strlen(res) != strlen(pkt1) || res != pkt1) exit(0);


# Send the first packet and check the return.
send(socket:soc, data:pkt1);
res = recv(socket:soc, length:512, min:64);
pkt2 = 
  mkdword(2) + mkdword(2) + 
  mkdword(0) + mkdword(1) +
  mkdword(0) + mkdword(0x4000000) + 
  mkdword(0x4000000) + mkdword(0) +
  mkdword(0) + mkdword(0) + 
  mkdword(0) + mkdword(0) +
  mkdword(0) + mkdword(0) + 
  mkdword(0) + mkdword(0);
if (strlen(res) != strlen(pkt2) || res != pkt2) exit(0);


# Send a second packet and check the return.
pkt2 = insstr(pkt2, mkdword(3), 0, 3);
send(socket:soc, data:pkt2);
pkt3 = insstr(pkt2, mkdword(1), 0, 3);
res = recv(socket:soc, length:512, min:64);
close(soc);
if (strlen(res) != strlen(pkt3) || res != pkt3) exit(0);


# This must be rvd since we've gotten the three packets we expected.
register_service(port:port, ipproto:"tcp", proto:"rvd");
security_note(port);
