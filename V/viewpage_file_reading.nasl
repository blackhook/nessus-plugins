#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11472);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-1545");
  script_bugtraq_id(7191);

  script_name(english:"Nukestyles.com viewpage.php Addon for PHP-Nuke File Parameter Traversal Arbitrary File Access");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to access arbitrary files from the remote system.");
  script_set_attribute(attribute:"description", value:
"viewpage.php (part of Nukestyles.com addon for PHP-Nuke) does 
not filter user-supplied input.

As a result, an attacker may use it to read arbitrary files on
the remote host by supplying a bogus value to the 'file' parameter
of this CGI.");
  script_set_attribute(attribute:"solution", value:
"Do not use php-nuke.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpnuke:nukestyles_viewpage_module");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
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

if(!can_host_php(port:port))exit(0);

foreach dir ( cgi_dirs() )
{
  res = http_send_recv3(method:"GET", item:string(dir,"/viewpage.php?file=/etc/passwd"), port:port);
  if(isnull(res)) exit(1,"Null response to viewpage.php request");
  if (egrep(pattern:".*root:.*:0:[01]:.*", string:res[2]))
  {
    security_hole(port);
    exit(0);
  }
}
