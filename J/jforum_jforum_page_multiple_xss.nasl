#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72515);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-5337");
  script_bugtraq_id(58164);

  script_name(english:"JForum jforum.page start Parameter XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of JForum installed on the remote host fails to properly
sanitize user-supplied input to the 'start' parameter of the
'jforum.page' script.  An attacker may be able to leverage this to
inject arbitrary HTML and script code into a user's browser to be
executed within the security context of the affected site.

Note that the application is also likely to be affected by other
cross-site scripting vulnerabilities involving the same script but
different parameters.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodaylab.com/zdl-advisories/2012-5337.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jforum:jforum");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jforum_detect.nbin");
  script_require_keys("www/JForum");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:8080);
app = "JForum";

install = get_install_from_kb(
  appname:app,
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];
install_url = build_url(port:port, qs:dir);

xss_test = '"><script>alert("'+ SCRIPT_NAME +'")</script>';

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/jforum.page',
  qs       : 'action=insertSave&module=posts&forum_id=1&start=' + xss_test + '&topic_id=1&disable_html=1&quick=1&message',
  pass_str : 'name="start" value="' + xss_test + '"',
  pass_re  : ">Review message<"
);

if (!exploit)
{
  install_url = build_url(qs: dir + "/", port: port);
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}
