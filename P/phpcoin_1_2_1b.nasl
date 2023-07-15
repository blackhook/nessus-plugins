#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17246);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2005-0669",
    "CVE-2005-0670",
    "CVE-2005-0932",
    "CVE-2005-0933",
    "CVE-2005-0946",
    "CVE-2005-0947"
  );
  script_bugtraq_id(12686, 12917);

  script_name(english:"phpCOIN <= 1.2.1b Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application affected by several
flaws.");
  script_set_attribute(attribute:"description", value:
"The remote host is running phpCOIN version 1.2.1b or older.  These
versions suffer from several vulnerabilities, among them :

  - A Local File Include Vulnerability
    An attacker can execute arbitrary code in the context of the
    web server user by passing the name of a script or file through 
    the 'page' parameter of the 'auxpage.php' script.

  - Multiple SQL injection vulnerabilities.
    By calling the 'faq' module with a specially crafted 
    'faq_id' parameter or the 'pages' or 'site' modules with a 
    specially crafted 'id' parameter, a remote attacker may be
    able to manipulate SQL queries used by the program, thereby 
    revealing sensitive information or even corrupting the
    database.

  - Multiple cross-site scripting vulnerabilities.
    A remote attacker may be able to inject arbitrary code
    into the 'helpdesk' and 'mail' modules as well as the 
    'login.php' script by appending it to a valid request.
    Successful exploitation may allow an attacker to steal
    authentication cookies or misrepresent site content.");
  # http://web.archive.org/web/20070921115306/http://www.gulftech.org/?node=research&article_id=00065-03292005
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60d5d944");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2005/Mar/520");
  script_set_attribute(attribute:"see_also", value:"http://forums.phpcoin.com//index.php?showtopic=4210");
  script_set_attribute(attribute:"solution", value:
"Apply the 2005-03-14 fix file or later for phpCOIN v1.2.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:coinsoft_technologies:phpcoin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

n = 0;
cgi[n] = "/mod.php";   qs[n++] = "mod=helpdesk&mode=new%22%3E";
cgi[n] = "/mod.php";   qs[n++] = "mod=mail&mode=reset&w=user%22%3E";
cgi[n] = "/login.php"; qs[n++] = "w=user&o=login&e=u%22%3E";

port = get_http_port(default:80, php: 1, no_xss: 1);

# Search for phpCOIN.
foreach dir (cgi_dirs()) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If the main page is from phpCOIN...
  if ('<meta name="generator" content="phpcoin">' >< res) {

    # Try XSS various exploits.
    # nb: various ways to popup a window with "Nessus was here"
    xss = "%3cscript%3ewindow.alert('Nessus%20was%20here')%3c/script%3e";

    for (i = 0; i < n; i ++) {
      if (test_cgi_xss(port: port, cgi: cgi[i], qs: qs[i]+xss, 
      	 dirs: make_list(dir), high_risk: 1, sql_injection: 1, 
      	 pass_str: "<script>window.alert('Nessus was here')</script>")) {
        exit(0);
      }
    }
  }
}
