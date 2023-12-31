#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10327);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2000-0149");
  script_bugtraq_id(977);

  script_name(english:"Zeus Web Server Null Byte Request CGI Source Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Zeus Web Server. 

Versions 3.1.x to 3.3.5 of this web server are vulnerable to a bug that
allows an attacker to view the source code of CGI scripts.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2000/Feb/153");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zeus 3.3.5a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/02/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zeus_technologies:zeus_web_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2000-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/zeus");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(banner)
{ 
  if(egrep(pattern:"Server *:.*Zeus/3\.[1-3][^0-9]", string:banner))
   security_warning(port);
}
