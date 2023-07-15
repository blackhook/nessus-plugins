#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19760);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2005-3019",
    "CVE-2005-3020",
    "CVE-2005-3024",
    "CVE-2005-3025"
  );
  script_bugtraq_id(14872, 14874);

  script_name(english:"vBulletin <= 3.0.9 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to
several flaws.");
  script_set_attribute(attribute:"description", value:
"The version of vBulletin installed on the remote host fails to
properly sanitize user-supplied input to a number of parameters and
scripts before using it in database queries and to generate dynamic
HTML.  An attacker can exploit these issues to launch SQL injection
and cross-site scripting attacks against the affected application. 
Note that the affected scripts require moderator or administrator
access, with the exception of 'joinrequests.php'.");
  script_set_attribute(attribute:"see_also", value:"http://morph3us.org/advisories/20050917-vbulletin-3.0.8.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vBulletin 3.0.9 to resolve many but not all of these issues.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-3019");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jelsoft:vbulletin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof..");

  script_dependencies("vbulletin_detect.nasl");
  script_require_keys("www/vBulletin");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php: TRUE);

# Test an install.
install = get_kb_item_or_exit("www/"+port+ "/vBulletin");
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: 3.0.9 and below are affected.
  if (ver =~ "^([0-2]\.|3\.0\.[0-9]($|[^0-9]))") {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
