#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(11134);
  script_version ("1.15");
 
  script_name(english:"QMTP/QMQP Server Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A QMTP/QMQP server is running on this port." );
 script_set_attribute(attribute:"description", value:
"A QMTP/QMQP server is running on this port.
QMTP is a proposed replacement of SMTP by D.J. Bernstein.

** Note that Nessus only runs SMTP tests currently." );
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/09/22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"asset_inventory", value:"True");
script_end_attributes();

  script_summary(english: "Detect QMTP servers");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2002-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Service detection");
  script_dependencies("find_service1.nasl", "find_service2.nasl", "smtp_settings.nasl");
  script_require_ports(209, 628);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("network_func.inc");

function netstr(str)
{
  local_var	l;

  l = strlen(str);
  return strcat(l, ":", str, ",");
}

global_var	tested;
tested = make_list();

function test(port)
{
  local_var	soc, r, msg, srv;

  if (tested[port]) return;
  tested[port] = 1;

  soc = open_sock_tcp(port);
  if (!soc) return;

  local_var from_email = get_kb_item('SMTP/headers/From');
  local_var to_email = get_kb_item('SMTP/headers/To');
  if (!from_email) from_email = 'nessus@example.org';
  if (!to_email) to_email = 'postmaster@example.com';

  msg = strcat(netstr(str: "
Message-ID: <1234567890.666." + from_email + ">
From: " + from_email + "
To: " + to_email + "

Nessus is probing this server.
"),
  netstr(str: from_email),
  netstr(str: netstr(str: to_email)));
  # QMQP encodes the whole message once more
  if (port == 628)
  {
     msg = netstr(str: msg);
     srv = "QMQP";
  }
  else
    srv = "QMTP";

  send(socket: soc, data: msg);
  r = recv(socket: soc, length: 1024);
  close(soc);

  if (preg(pattern: "^[1-9][0-9]*:[KZD]", string: r))
  {
    security_note(port);
    register_service(port: port, proto: srv);
  }

  if (preg(pattern: "^[1-9][0-9]*:K", string: r))
  {
    # K: Message accepted for delivery
    # Z: temporary failure
    # D: permanent failure
    set_kb_item(name: "QMTP/relay/"+port, value: TRUE);
   }
}

ports = get_kb_list("Services/QMTP");
if (! isnull(ports))
  foreach port (ports)
    if (service_is_unknown(port: port) && get_port_state(port))
      test(port: port);

ports = get_kb_list("Services/QMQP");
if (! isnull(ports))
  foreach port (ports)
    if (service_is_unknown(port: port) && get_port_state(port))
      test(port: port);

foreach port (make_list(209, 628))
  if (service_is_unknown(port: port) && get_port_state(port))
    test(port: port);
