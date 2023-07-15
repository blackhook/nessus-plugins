#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12045);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_cve_id("CVE-2004-2072");
  script_bugtraq_id(9588);

  script_name(english:"Mambo Site Server itemid Parameter XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a cross-
site scripting attack.");
  script_set_attribute(attribute:"description", value:
"An attacker may use the installed version of Mambo Site Server to
perform a cross-site scripting attack on the remote host.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "cross_site_scripting.nasl");
  script_require_keys("www/mambo_mos");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0, "The web server on port "+port+" is vulnerable to XSS");
if(!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0, "Mambo is not installed on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 url = string(dir, "/index.php?option=content&task=view&id=1&Itemid=<script>foo</script>");
 w = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 buf = w[2];
 
 if ( "<script>foo</script>" >< buf)
 {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
}
