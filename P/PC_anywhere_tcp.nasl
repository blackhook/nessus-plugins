#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10794);
  script_version("1.46");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Symantec pcAnywhere Detection (TCP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has pcAnywhere enabled.");
  script_set_attribute(attribute:"description", value:
"Symantec pcAnywhere allows a Windows user to remotely obtain a
graphical login (and therefore act as a local user on the remote
host).");
  script_set_attribute(attribute:"solution", value:
"Disable pcAnywhere if you do not use it, and do not allow this service
to run across the Internet.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2001/10/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:pcanywhere");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "find_service1.nasl");
  script_require_ports("Services/unknown", 5631);

  exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");
include ("byte_func.inc");

function unencrypted_connections_report()
{
  var r, types, type, soc, res;

  types = [
    ['\x6f\x61\x00\x09\x00\xfe\x00\x00\xff\xff\x00\x00\x00\x00', '<None>'],
    ['\x6f\x61\x00\x09\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00', 'pcAnywhere encoding']
  ];

  res = '';
  foreach type (types)
  {
    sleep(5); # Wait for pcanywhere to accept connections again.
    soc = open_sock_tcp(port);
    if (!soc) exit(0);
    send(socket:soc, data:'\x00\x00\x00\x00');
    recv(socket:soc, length: 1024, timeout:10);
    send(socket:soc, data:'\x6f\x06\xff');
    recv(socket:soc, length: 1024, timeout:10);
    send(socket:soc, data:type[0]);
    r = recv(socket:soc, length: 1024, timeout:10);

    close(soc);
    if(!isnull(r) && "Host is denying connection" >!< r)
    {
      res += '  ' + type[1] + '\n';
    }
  }

  if (strlen(res) > 0)
  {
    res = 'pcAnywhere supports unencrypted connections of the following type(s) :\n' + res;
    return res;
  }

  return NULL;
}

if (thorough_tests)
{
  port = get_unknown_svc(5631);
  if (!port) exit(0);
}
else port = 5631;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);

# Any script that uses this service requires a few seconds for the service to get back into the 'accepting connections' state
sleep(5);

soc = open_sock_tcp(port);
if (!soc) exit(0);

data =  mkdword(0);

send(socket:soc, data:data);
buf = recv(socket:soc, length:4096);
close(soc);
if ("005808007d080d0a002e08" >< hexstr(buf))
{
  register_service (port:port, proto:"pcanywheredata");
  security_note(port);

  if (get_kb_item("Settings/PCI_DSS"))
  {
    pci_report = unencrypted_connections_report();
    if (!isnull(pci_report))
    {
      set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);
    }
  }
}
