#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21631);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-2857");
  script_bugtraq_id(18264);

  script_name(english:"LifeType index.php articleId Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running LifeType, an open source blogging platform
written in PHP. 

The version of LifeType installed on the remote host fails to sanitize
user-supplied input to the 'articleId' parameter of the 'index.php'
script before using it to construct database queries.  Regardless of
PHP's 'magic_quotes_gpc' setting, an unauthenticated attacker can
exploit this flaw to manipulate database queries and, for example,
recover the administrator's password hash.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/435874/30/0/threaded");
  # http://web.archive.org/web/20100724043319/http://www.lifetype.net/blog.php/lifetype_development_journal/2006/06/04/important_security_upgrade_lifetype_1.0.5_released
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6575bed4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LifeType version 1.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lifetype:lifetype");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/lifetype", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  magic = unixtime();
  exploit = string("/**/UNION/**/SELECT/**/", magic, ",1,1,1,1,1,1,1--");
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "op=ViewArticle&",
      "articleId=9999", urlencode(str:exploit), "&",
      "blogId=1"
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # it looks like LifeType and...
    '<meta name="generator" content="lifetype' >< res &&
    # it uses our string for an article id
    string('articleId=', magic, '&amp;blogId=1">Permalink') >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
