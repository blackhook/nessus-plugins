#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22878);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-5444");
  script_bugtraq_id(20617);

  script_name(english:"Asterisk Skinny Channel Driver (chan_skinny) get_input Function Remote Overflow");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by a
heap overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The chan_skinny channel driver included in the version of Asterisk
running on the remote host does not properly validate the length
header in incoming packets.  An unauthenticated, remote attacker may be
able to leverage this flaw to execute code on the affected host
subject to the privileges under which Asterisk runs, generally root.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/449127/30/0/threaded");
  # http://web.archive.org/web/20061108144940/http://www.asterisk.org/node/109
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5f58960");
  script_set_attribute(attribute:"solution", value:
"Either disable the chan_skinny channel driver or upgrade to Asterisk
1.2.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2006-2022 Tenable Network Security, Inc.");

  script_dependencies("skinny_detect.nasl");
  script_require_ports("Services/skinny", 2000);

  exit(0);
}


include("byte_func.inc");


port = get_kb_item("Services/skinny");
if (!port) port = 2000;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a weird request; a vulnerable version will respond while 
# a patched one will silently drop it.
device = "SEP6E6573737573";
ip = split(compat::this_host(), sep:'.', keep:FALSE);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
req = mkdword(0x80000000) +            # message length
  mkdword(0) +                         # reserved
  mkdword(1) +                         # message id (1 => station register)
    device + mkbyte(0) +               #   name
    mkdword(0) +                       #   station userid
    mkdword(1) +                       #   station instance
    mkbyte(int(ip[0])) +               #   client ip
      mkbyte(int(ip[1])) + 
      mkbyte(int(ip[2])) + 
      mkbyte(int(ip[3])) + 
    mkdword(2) +                       #   device type (2 => 12SPplus)
    mkdword(0);                        #   max streams
req += crap(1008-strlen(req));
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);


# There's a problem if we get a response.
if (
  strlen(res) > 12 && 
  getdword(blob:res, pos:0) == strlen(res) - 8 &&
  (
    getdword(blob:res, pos:8) == 0x81 ||
    (getdword(blob:res, pos:8) == 0x9d && string("No Authority: ", device) >< res)
  )
) security_hole(port);
