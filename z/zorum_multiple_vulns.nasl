#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17312);
  script_version("1.37");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2005-0675",
    "CVE-2005-0676",
    "CVE-2005-0677",
    "CVE-2005-2651",
    "CVE-2005-4619",
    "CVE-2006-3332"
  );
  script_bugtraq_id(
    12777,
    14601,
    16131,
    18681
  );

  script_name(english:"Zorum <= 3.5 Multiple Remote Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
numerous flaws.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Zorum, an open source electronic forum
written in PHP. 

The version of Zorum installed on the remote host is prone to numerous
flaws, including remote code execution, privilege escalation, and SQL
injection.");
  script_set_attribute(attribute:"see_also", value:"https://securitytracker.com/id?1013365");
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/zorum.html");
  # http://web.archive.org/web/20061024204453/http://pridels.blogspot.com/2005/11/zorum-forum-35-rollid-sql-inj-vuln.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2771c30c");
  # http://web.archive.org/web/20061024195444/http://pridels.blogspot.com/2006/06/zorum-forum-35-vuln.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b262f66c");
  script_set_attribute(attribute:"solution", value:
"Remove the software as it is no longer maintained.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpoutsourcing:zorum");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = string('<script>alert("', SCRIPT_NAME, '")</script>');
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);


# Loop through directories.
if (thorough_tests) dirs = make_list("/zorum", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

  # Try various XSS exploits.
exploits = make_list(
    'list="/%3e' + exss,
    'method="/%3e' + exss,
    'method=markread&list=zorumuser&fromlist=secmenu&frommethod="/%3e' + exss
  );

foreach exploit (exploits)
{
  if ( test_cgi_xss(port: port, cgi: "/index.php", dirs: dirs, qs: exploit,
       sql_injection: 1, high_risk: 1,
       pass_str: string("Method is not allowed : ", xss)) ) exit(0);
}
