#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(10051);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"CVS pserver Detection");

  script_set_attribute(attribute:"synopsis", value:
"A CVS pserver is listening on the remote port.");
  script_set_attribute(attribute:"description", value:
"Concurrent Versions System (CVS), an open source versioning system,
is running on the remote port. The CVS server can be accessed either
using third-party tools (e.g., RSH or SSH) or via the 'pserver'
protocol, which is unencrypted.");
  script_set_attribute(attribute:"solution", value:
"Use CVS on top of RSH or SSH if possible.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cvs:cvs");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/cvspserver", 2401);

  exit(0);
}

include("audit.inc");

#
# The script code starts here
#
port = get_kb_item("Services/cvspserver");
if(!port) port = 2401;

if ( ! get_port_state(port) ) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if ( ! soc ) audit(AUDIT_SOCK_FAIL, port);

req = string("BEGIN AUTH REQUEST\n",
  "/\n",
  "\n",
  "A\n",
  "END AUTH REQUEST\n");
send(socket:soc, data:req);
r = recv_line(socket:soc, length:4096);
close(soc);

if("repository" >< r || "I HATE" >< r)
{
  pci_report = 'The remote cvspserver service on port ' + port + ' accepts cleartext logins.';
  set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);
  security_note(port);
  exit(0);
}

audit(AUDIT_NOT_DETECT, "cvspserver", port);
