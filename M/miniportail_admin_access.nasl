#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11623);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-0272");

  script_name(english:"miniPortail admin.php Cookie Manipulation Security Bypass");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running MiniPortal, a PHP application for managing
a web portal.

It is possible to bypass admin authentication by setting a cookie
with a value of 'adminok' on admin.php.  A remote attacker could
exploit this to gain administrative privileges on this host.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/May/93");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:miniportal:miniportal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

foreach d (cgi_dirs())
{
 set_http_cookie(name: "miniPortailAdmin", value: "adminok");
 r = http_send_recv3(method: "GET", item: d+ "/admin/admin.php", port: port);
 if (isnull(r)) exit(0);
 if (egrep(pattern:".*admin\.php\?.*pg=dbcheck", string: r[2]))
 	{
	security_hole(port);
	exit(0);
	}
 }
