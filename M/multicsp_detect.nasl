#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10418);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2000-0109");
  script_bugtraq_id(1080);

  script_name(english:"Standard & Poor's ComStock MultiCSP Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be running a client application for a stock
quote server.");
  script_set_attribute(attribute:"description", value:
"The remote host seems to be a Standard & Poor's MultiCSP system.

Make sure only authorized systems can connect to it.

In addition, these units ship with several default accounts with a
blank or easily guessed password. However, Nessus has not checked 
for these.");
  script_set_attribute(attribute:"solution", value:
"Protect this host by a firewall");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:comstock:multicsp");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2000-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}

#
# The script code starts here
#
include("telnet_func.inc");

port = get_kb_item("Services/telnet");
if(!port)port = 23;
if (get_port_state(port))
{
 banner = get_telnet_banner(port: port);
 if(banner)
   {
   if("MCSP - Standard & Poor's ComStock" >< banner)
      security_hole(port:port, extra:'The remote telnet banner is :\n' + banner);
   }
}
