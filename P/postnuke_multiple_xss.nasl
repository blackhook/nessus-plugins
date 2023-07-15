#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11743);
  script_version("1.32");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(7898, 7901);

  script_name(english:"PostNuke < 0.7.2.3 Multiple Script XSS");

  script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross-site scripting.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of PostNuke that is vulnerable
to various cross-site scripting attacks.

An attacker may use these flaws to steal the cookies of the legitimate
users of this website.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostNuke 0.7.2.3-Phoenix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:postnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postnuke_detect.nasl", "cross_site_scripting.nasl");
  script_require_keys("www/postnuke");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if (!can_host_php(port:port))exit(0);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
dir = stuff[2];

test_cgi_xss(port: port, dirs: make_list(dir), cgi: "/modules.php",
 pass_str: "<img src=javascript:foo;>",
 qs: "op=modload&name=FAQ&file=index&myfaq=yes&id_cat=1&categories=%3cimg%20src=javascript:foo;%3E&parent_id=0");
