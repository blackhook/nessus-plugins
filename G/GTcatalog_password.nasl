#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: GTcatalog (PHP)
# Date: Mon, 03 Mar 2003 15:52:29 +0100
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11509);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"GTcatalog password.inc Direct Request Password Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts GTcatalog, a catalog management
system written in PHP.

It is possible to obtain the password of the remote GTcatalog
installation by directly requesting the file 'password.inc'.

An attacker may leverage this issue to obtain the password and gain
administrative access to the affected application.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/Mar/16");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:chris_mac:gimescripts_shopping_catalog");
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

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "Web server does not support PHP scripts.");

function check(loc)
{
 local_var r;
 r = http_send_recv3(method:"GET", item:string(loc, "/password.inc"),
 		port:port);			
 if (isnull(r)) exit(1, "The web server failed to respond.");

 if("globalpw" >< r[2])
 {
 	security_warning(port);
	exit(0);
 }
}


dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir) 
  dirs = make_list(dirs, string(d, "/gtcatalog"), string(d, "/GTcatalog"));
dirs = list_uniq(make_list(dirs, "", "/gtcatalog", "/GTcatalog"));

foreach dir (dirs)
{
 check(loc:dir);
}
