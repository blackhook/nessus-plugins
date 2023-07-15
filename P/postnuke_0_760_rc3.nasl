#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18360);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2005-1621",
    "CVE-2005-1697",
    "CVE-2005-1698",
    "CVE-2005-1699",
    "CVE-2005-1700"
  );
  script_bugtraq_id(13706, 13789);

  script_name(english:"PostNuke <= 0.760 RC4a Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to several
attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running PostNuke version 0.760 RC4a or older. 
These versions suffer from several vulnerabilities, among them :

  - Multiple Remote Code Injection Vulnerabilities
    An attacker can read arbitrary files on the remote and 
    possibly inject arbitrary PHP code remotely.

  - SQL Injection Vulnerabilities
    Weaknesses in the 'Xanthia' and 'Messages' modules allow 
    attackers to affect database queries, possibly resulting
    in the disclosure of sensitive information such as user
    passwords and even execution of arbitrary PHP code on
    the remote host.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can inject arbitrary script code into the
    browser of users leading to disclosure of session 
    cookies, redirection to other sites, etc.

  - Multiple Path Disclosure Vulnerabilities
    An attacker can discover details about the underlying
    installation directory structure by calling various
    include scripts directly.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2005/May/196");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2005/May/253");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2005/May/254");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2005/May/255");
  script_set_attribute(attribute:"see_also", value:"http://community.postnuke.com/Article2691.htm");
  script_set_attribute(attribute:"solution", value:
"Apply the security fix package referenced in the article above to
upgrade to PostNuke version 0.750.0b.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:postnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postnuke_detect.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  test_cgi_xss(port: port, cgi: "/index.php", 
 pass_re: "root:.+:0:", high_risk: 1, sql_injection: 1, 
 qs: string(
        "module=Blocks&",
        "type=lang&",
        "func=../../../../../../../../../../../../etc/passwd%00"
      )
  );
}
