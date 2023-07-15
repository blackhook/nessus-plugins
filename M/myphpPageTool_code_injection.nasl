#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11310);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-4947");

  script_name(english:"myphpPageTool /doc/admin/index.php ptinclude Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
a remote file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server appears to be hosting myphpPageTool. The
installed version fails to properly sanitize user-supplied input to
the 'ptinclude' parameter of the '/doc/admin/index.php' script. An
attacker may use this flaw to inject arbitrary code in the remote host
and gain a shell with the privileges of the web server if the server
has 'register_globals' enabled.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/Feb/5");
  script_set_attribute(attribute:"solution", value:
"Turn off the 'register_globals' option in PHP.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-4947");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:myphppagetool:myphppagetool");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if(!can_host_php(port:port))exit(0);

function check(loc)
{
  local_var res;
  
  res = http_send_recv3(method:"GET", item:string(loc, "/doc/admin/index.php?ptinclude-http://example.com"), port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if("http://example.com/ptconfig.php" >< res[2])
  {
    security_hole(port);
    exit(0);
  }
}


dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir)
{
  dirs = make_list(dirs, string(d, "/myphpPageTool"));
}

dirs = make_list(dirs, "", "/myphpPageTool");

foreach dir (dirs)
{
  check(loc:dir);
}
