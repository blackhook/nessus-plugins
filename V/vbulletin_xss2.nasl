#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

#  Ref: Arab VieruZ <arabviersus@hotmail.com>
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14833);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-1824");
  script_bugtraq_id(6226);

  script_name(english:"vBulletin memberlist.php what Parameter XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
cross-site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The remote version of vBulletin is vulnerable to a cross-site
scripting issue due to a failure of the application to properly
sanitize user-supplied URI input.  As a result of this vulnerability,
it is possible for a remote attacker to create a malicious link
containing script code that will be executed in the browser of an
unsuspecting user when followed.  This may facilitate the theft of
cookie-based authentication credentials as well as other attacks.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Nov/298");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jelsoft:vbulletin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("cross_site_scripting.nasl", "vbulletin_detect.nasl");
  script_require_keys("www/vBulletin");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
  
# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  test_cgi_xss(port: port, dirs: make_list(dir), cgi: "/memberlist.php", 
 qs: "s=23c37cf1af5d2ad05f49361b0407ad9e&what=<script>foo</script>",
 pass_str: "<script>foo</script>" );
}
