#
# (C) Tenable Network Security, Inc.
#

# Ref (for the MITM attack) :
#  To: bugtraq@securityfocus.com
#  Subject: Microsoft Terminal Services vulnerable to MITM-attacks.
#  From: Erik Forsberg <forsberg+btq@cendio.se>
#  Date: 02 Apr 2003 00:05:44 +0200
#

include("compat.inc");

if (description)
{
  script_id(10940);
  script_version("1.39");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_name(english:"Windows Terminal Services Enabled");
  script_summary(english:"Connects to the remote terminal server");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has Terminal Services enabled.");
  script_set_attribute(attribute:"description", value:
"Terminal Services allows a Windows user to remotely obtain a graphical
login (and therefore act as a local user on the remote host).

If an attacker gains a valid login and password, this service could be
used to gain further access on the remote host.  An attacker may also
use this service to mount a dictionary attack against the remote host
to try to log in remotely.

Note that RDP (the Remote Desktop Protocol) is vulnerable to
Man-in-the-middle attacks, making it easy for attackers to steal the
credentials of legitimate users by impersonating the Windows server.");
  script_set_attribute(attribute:"solution", value:
"Disable Terminal Services if you do not use it, and do not allow this
service to run across the Internet.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_2000_terminal_services");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2002-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 3389);
  script_exclude_keys("global_settings/disable_service_discovery");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("spad_logger.inc");

var logger = new("spad_logger::logger");
var ports = make_list(3389);
var rdpctr = 0;
var os_remote = get_kb_item('Host/OS');

# Make sure it's Windows
if (get_kb_item("SMB/not_windows") || 'Windows' >!< os_remote)
  audit(AUDIT_HOST_NOT, "Windows");

if (!get_kb_item("global_settings/disable_service_discovery"))
{
  var unknown_svc_list = get_kb_list("Services/unknown");
  if (!empty_or_null(unknown_svc_list)) ports = make_list(ports, unknown_svc_list);
}

var port, r, soc, rlen;
foreach port (ports)
{
  if (!get_port_state(port)) continue;

  soc = open_sock_tcp(port, transport:ENCAPS_IP,timeout:60);
  if (soc)
  {
    logger.log("Attempting RDP connection request on " + port);
    send(socket:soc, data:
      # TPKT Header [T.123]
      '\x03' + # version number (always 0000 0011)
      '\x00' + # reserved (always 0)
      '\x00\x13' + # Length (including header) - big endian

      # Connection request TPDU
      '\x0e' + # LI (length indicator)
      '\xe0' + # CR (1110) + CDT (0000 = class 0 or 1)
      '\x00\x00' + # DST REF (always 0)
      '\x00\x00' + # SRC REF
      '\x00' + # Class option (class 0)

      # RDP negotiation request
      '\x01' + # Type (must be 1)
      '\x00' + # Flags (must be 0)
      '\x08\x00' + # Length (must be 8) - little endian
      mkdword(0) # Requested protocols (0 = standard)
    );

    r = recv(socket:soc, length:11, timeout:60); # Long timeout; We are only accepting the TPKT and COTP packets
    close(soc);

    if(!r)
      continue;

    rlen = strlen(r);

    if(rlen != 11        || # TPKT header [4] + TPDU header [7]
       ord(r[0]) != 0x03 || # TPKT version number
       ord(r[1]) != 0x00)   # Reserved
    {
      logger.log("TPKT header in response on port " + port + " does not look like TPKT ["+hexstr(substr(r,0,3))+"]");
      continue;
    }
    if (ord(r[5]) != 0xd0) # PDU Type: CC Connect Confirm (0xd) + 0x0
    {
      logger.log("COTP header incorrect in response on port " + port + " ["+hexstr(substr(r,4,10))+"]");
      continue;
    }

    rdpctr++;
    security_note(port);
    register_service(port:port, proto:"msrdp");
  }
}

if (rdpctr == 0)
  audit(AUDIT_NOT_DETECT, "RDP");