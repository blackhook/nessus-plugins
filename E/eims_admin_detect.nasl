#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#



include('deprecated_nasl_level.inc');
include("compat.inc");

if (description) {
  script_id(20727);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Eudora Internet Mail Server Admin Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"A Eudora Internet Mail Server Admin server is running on the remote
host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Eudora Internet Mail Server, a mail server
for Macs, and its Admin server is listening on this port.  Since the
Admin server is used to administer the mail server, possibly remotely,
you should limit access to it.");
  script_set_attribute(attribute:"see_also", value:"http://www.eudora.co.nz/");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port if possible.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:eudora:internet_mail_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 4199);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) {
  port = get_unknown_svc(4199);
  if (!port) exit(0);
}
else port = 4199;
if (!get_tcp_port_state(port)) exit(0);


# Read the banner and make sure it looks like EIMS.
soc = open_sock_tcp(port);
if (!soc) exit(0);

res = recv(socket:soc, length:64);
if (
  !res || 
  strlen(res) != 28 || 
  substr(res, 0, 3) != raw_string(0x00, 0x1c, 0x00, 0x01)
) exit(0);
o = split(get_host_ip(), sep:".", keep:FALSE);
oraw = raw_string(int(o[0]), int(o[1]), int(o[2]), int(o[3]));
if (substr(res, 20, 23) != oraw) exit(0);


# Try to connect with an invalid password.
req = raw_string(
  0x00, 0x18,
  0x00, 0x02, 0x3a, 0xf1,
  0x41, 0xa7, 0x08, 0xe9,
  0xb4, 0x7d, 0x29, 0x11,
  0xe6, 0x95, 0x1a, 0xdd,
  0x59, 0xe5, 0x4d, 0xa3,
  0x3d, 0x95
);
send(socket:soc, data:req);


# Register the service if it looks like a failure.
res = recv(socket:soc, length:64);
if (
  res &&
  strlen(res) == 24 &&
  substr(res, 2, 7) == raw_string(0x00, 0x00, 0x3a, 0xf1, 0x41, 0xa7)
) {
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"eims-admin");

  security_note(port);
}
