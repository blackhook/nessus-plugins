#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22233);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-4214");
  script_bugtraq_id(19542);

  script_name(english:"Zen Cart ipn_main_handler.php custom SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The version of Zen Cart installed on the remote host fails to properly
sanitize input to the 'custom' parameter of the 'ipn_main_handler.php'
script before using it in a database query.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated attacker may
be able to exploit this issue to uncover sensitive information such as
password hashes, modify data, launch attacks against the underlying
database, etc.");
  script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00109-08152006");
  script_set_attribute(attribute:"see_also", value:"https://www.zen-cart.com/showthread.php?43579-Security-Patches-for-v1-3-0x");
  script_set_attribute(attribute:"solution", value:
"Apply the security patches listed in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zen-cart:zen_cart");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 Tenable Network Security, Inc.");

  script_dependencies("zencart_detect.nasl");
  script_require_keys("www/zencart");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (get_kb_item("www/no404/" + port)) exit(0, "The web server on port "+port+" does not return 404 codes");


# Test an install.
install = get_kb_item(string("www/", port, "/zencart"));
if (isnull(install)) exit(0, "Zencart was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/ipn_main_handler.php");

  r = http_send_recv3(port:port, method: "GET", item: url);
  if (isnull(r)) exit(0);

  # If it does...
  #
  # nb: the script only responds to POSTs.
  if (egrep(string:r[0], pattern:"^HTTP/.* 200 OK"))
  {
    # Try to exploit the flaw to generate a syntax error.
    postdata = string(
      "custom=nessus='", SCRIPT_NAME
    );
    r = http_send_recv3(method: "POST", port: port, version: 11, item: url, data: postdata, add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
    if (isnull(r)) exit(0);

    # There's a problem if we see an error message with our script name.
    if (string("right syntax to use near '", SCRIPT_NAME, "''") >< r[2])
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    }
  }
}
