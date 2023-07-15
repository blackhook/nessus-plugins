#%NASL_MIN_LEVEL 70300
#
# This script was written by Michael Scheidell SECNAP Network Security
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/12/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)
# - Add MSKB script_xref (8/29/17)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11053);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0698");
  script_bugtraq_id(5306);
  script_xref(name:"MSFT", value:"MS02-037");
  script_xref(name:"MSKB", value:"326322");

  script_name(english:"MS02-037: Microsoft Exchange EHLO Long Hostname Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"A security vulnerability results because of an unchecked 
buffer in the IMC code that generates the response to the
EHLO protocol command. If the buffer were overrun with data 
it would result in either the failure of the IMC or could allow 
the attacker to run code in the security context of the IMC,
which runs as Exchange5.5 Service Account.

** Nessus only uses the banner header to determine
   if this vulnerability exists and does not check
   for or attempt an actual overflow.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2002/ms02-037");
  script_set_attribute(attribute:"solution", value:
"See the vendor advisory for patch information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/07/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2002-2022 SECNAP Network Security, LLC");

  script_dependencies("find_service1.nasl", "smtpserver_detect.nasl");
  script_require_keys("SMTP/microsoft_esmtp_5");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
data = get_smtp_banner(port:port);
if(!data)exit(0);

if(!egrep(pattern:"^220.*Microsoft Exchange Internet.*", 
	 string:data))exit(0);

# needs to be 5.5.2656.59 or GREATER.
# this good:

#220 proliant.fdma.com ESMTP Server (Microsoft Exchange
#Internet Mail Service 5.5.2656.59) ready

#this old:

#220 proliant.fdma.com ESMTP Server (Microsoft Exchange
#Internet Mail Service 5.5.2653.13) ready

if(egrep(string:data, pattern:"Service.5\.[6-9]"))
  exit(0);

if(egrep(string:data, pattern:"Service.5\.5\.[3-9]"))
  exit(0);

if(egrep(string:data, pattern:"Service.5\.5\.2[7-9]"))
  exit(0);

if(egrep(string:data, pattern:"Service.5\.5\.26[6-9]"))
  exit(0);

if(egrep(string:data, pattern:"Service.5\.5\.265[6-9]"))
  exit(0);
security_hole(port);

