#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10094);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"GirlFriend Backdoor Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a backdoor installed.");
  script_set_attribute(attribute:"description", value:
"The remote host has the GirlFriend backdoor installed. This backdoor
allows anyone to partially take control of the remote system. An
attacker could use it to steal your password or prevent your system
from working properly.");
  script_set_attribute(attribute:"solution", value:
"Open regedit to HKLM\Software\Microsoft\Windows\CurrentVersion\Run and
look for a value named 'Windll.exe' with the data
'c:\windows\windll.exe'. Reboot to DOS and delete the
'c:\windows\windll.exe' file then boot to Windows and remove the
'Windll.exe' registry value.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"1999/07/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 1999-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_keys("Settings/ThoroughTests");
  script_require_ports(21554, 21544);

  exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

#1.0 beta
port = 21554;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:"ver", 3);
  a = recv_line(socket:soc, length:20);
  if("GirlFriend" >< a)security_hole(port);
  close(soc);
 }
}

#1.3 and 1.35
port = 21544;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:"ver", 3);
  a = recv_line(socket:soc, length:20);
  if("GirlFriend" >< a)security_hole(port);
  close(soc);
 }
}
