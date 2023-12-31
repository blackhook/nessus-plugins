#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10053);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"DeepThroat Backdoor Detection");

  script_set_attribute(attribute:"synopsis", value:
"A backdoor is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"DeepThroat is installed on the remote host.  This backdoor allows
anyone to perform actions such as reading files, reading the registry
and executing programs.  A remote attacker could use this to completely
control the system.");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20100116213058/http://xforce.iss.net:80/xforce/xfdb/2290");
  script_set_attribute(attribute:"solution", value:
"Use regedit or regedt32, and find 'SystemDLL32' in

  HKLM\Software\Microsoft\Windows\CurrentVersion\Run 

This value's data is the path of the file.  If you are infected by
DeepThroat 2 or 3, then the registry value is named 'SystemTray'. 

After cleaning the infected machine, you should manually find the root
cause of the initial infection.  Alternatively, you may wish to
completely rebuild the system, as the backdoor may have been used to
create other backdoors into the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"1999/07/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 1999-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_keys("Settings/ThoroughTests");

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include('global_settings.inc');

if (!thorough_tests) audit(AUDIT_THOROUGH);

port = 2140;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

data = raw_string(0x00,0x00);
soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

send(socket:soc, data:data, length:2);
result = recv(socket:soc, length:4096);
if("My Mouth is Open" >< result)security_hole(port:port, proto:"udp");
close(soc);
