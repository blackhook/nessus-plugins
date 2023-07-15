#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16273);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-0320", "CVE-2005-0321");
  script_bugtraq_id(12396);

  script_name(english:"IceWarp Web Mail Multiple Flaws (3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a webmail application that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running IceWarp Web Mail - a webmail solution
available for the Microsoft Windows platform.

The remote version of this software is vulnerable to multiple 
input validation issues that could allow an attacker to compromise the
integrity of the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/388751/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IceWarp Web Mail 5.3.3 or newer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:icewarp:webmail");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("icewarp_webmail_vulns.nasl");
  script_require_ports("Services/www", 32000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:32000);

version = get_kb_item("www/" + port + "/icewarp_webmail/version");
if ( ! version ) exit(0);
if ( ereg(pattern:"IceWarp Web Mail ([0-4]\.|5\.([0-2]\.|3\.[0-2][^0-9]))", string:version) )
	security_warning(port);
