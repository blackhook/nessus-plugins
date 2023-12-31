#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# References:
# From: Ryan Rounkles <ryan.rounkles@gmail.com>
# To: vuln-dev@securityfocus.com
# Date: Tue, 19 Oct 2004 09:39:46 -0700
# Subject: Denial of service in LANDesk 8
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15571);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"LANDesk idsintkm.dll Multiple Port Connection Remote DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"It was possible to crash the remote system by connecting
to every open port. This is known to bluescreen machines 
running LANDesk8 (In this case, connecting to two ports 
is enough)");
  script_set_attribute(attribute:"solution", value:
"Inform your software vendor(s) and patch your system");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_require_keys("Settings/ThoroughTests", "Settings/ParanoidReport");

  exit(0);
}

include('global_settings.inc');

if ( ! thorough_tests || report_paranoia < 2) exit(0);

start_denial();

i = 0;
ports = get_kb_list("Ports/tcp/*");
if(isnull(ports))exit(0);

foreach port (keys(ports))
{
 p = int(port - "Ports/tcp/");
 if (get_port_state(p))
  {
    s[i] = open_sock_tcp(p);
    if (s[i]) i ++;
  }
}


if ( i == 0 ) exit(0);
# display(i, " ports were open\n");

alive = end_denial();

if(!alive)
{
  security_hole(port);
  set_kb_item(name:"Host/dead", value:TRUE);
  exit(0);
}

for (j = 0; j < i; j ++)
  close(s[j]);
