#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15784);
  script_version("1.35");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2004-1537",
    "CVE-2004-1538",
    "CVE-2005-2683",
    "CVE-2005-2699",
    "CVE-2005-3552",
    "CVE-2005-3553",
    "CVE-2005-3554",
    "CVE-2005-4424",
    "CVE-2006-0785",
    "CVE-2006-0786",
    "CVE-2006-1507",
    "CVE-2006-1773"
  );
  script_bugtraq_id(
    11725,
    14629,
    15354,
    17291,
    17467
  );

  script_name(english:"PHP-Kit <= 1.6.1 RC2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several issues.");
  script_set_attribute(attribute:"description", value:
"The remote host is running PHP-Kit, an open source content management
system written in PHP. 

The remote version of this software is vulnerable to multiple remote
and local code execution, SQL injection and cross-site scripting
flaws.");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=bugtraq&m=110117116115493&w=2");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=bugtraq&m=112474427221031&w=2");
  script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_212005.80.html");
  # https://web.archive.org/web/20120402163601/http://retrogod.altervista.org/phpkit_161r2_incl_xpl.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d981cb2");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/429249/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Remove the application as it is no longer maintained.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpkit:phpkit");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port))exit(0);

loc = make_list();

# 1. Detect phpkit
if (thorough_tests) dirs = list_uniq(make_list("/phpkit", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 r = http_send_recv3(method:"GET", item:dir + "/include.php", port:port);
 if (isnull(r)) exit(0, "the web server did not answer");
 res = r[2];
 line = egrep(pattern:".*PHPKIT.* Version [0-9.]*", string:res);
 if ( line )
 {
  version = ereg_replace(pattern:".*PHPKIT.* Version ([0-9.]*).*", string:line, replace:"\1");
  if ( version == line ) version = "unknown";
  if ( dir == "" ) dir = "/";

  set_kb_item(name:"www/" + port + "/phpkit", value:version + " under " + dir);
  loc = make_list(dir, loc);
 }
}

# Now check the SQL injection

foreach dir (loc)
{
 r = http_send_recv3(method:"GET",item:dir + "/popup.php?img=<script>", port:port);
 if (isnull(r)) exit(0, "the web server did not answer");
 res = r[2];
 if  ( 'ALT="<script>" SRC="<script>"' >< res ) 
	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 r = http_send_recv3(method:"GET",item:loc + "/include.php?path=guestbook/print.php&id='", port:port);
 if (isnull(r)) exit(0, "the web server did not answer");
 res = r[2];
 if  ( "SELECT * FROM phpkit_gbook WHERE gbook_id='''" >< res )
	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
}
