#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59360);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(53546);

  script_name(english:"Liferay Portal upload_progress_poller.jsp XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Liferay Portal hosted on the remote web server fails
to properly sanitize input to the 'uploadProgressId' parameter of the
'upload_progress_poller.jsp' script. 

An attacker can leverage this issue by enticing a user to follow a
malicious URL, causing attacker-specified script code to run inside
the user's browser in the context of the affected site. Information
harvested this way may aid in launching further attacks.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/522726");
  # https://github.com/liferay/liferay-portal/commit/9f561f34a3c3c9908e2ed5d209c774494d09ea40
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30b86db5");
  script_set_attribute(attribute:"solution", value:
"Update to the newest version in Git or to 6.2.0 when it becomes
available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Liferay Users disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("liferay_detect.nasl");
  script_require_keys("www/liferay_portal");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get the ports that web servers have been found on, defaulting to
# what Liferay uses with Tomcat, their recommended bundle.
port = get_http_port(default:8080);

# Get details of the Liferay Portal install.
install = get_install_from_kb(appname:"liferay_portal", port:port, exit_on_fail:TRUE);
dir = install["dir"];

cgi = "/html/portal/upload_progress_poller.jsp";
xss = "a=1;alert(" + unixtime() + ");//";

# The ctrl_re is weak, but all this page has is html, body, and script
# tags with no attributes. The pass_str is the only other thing on the
# page.
exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : cgi,
  qs       : "uploadProgressId=" + xss,
  pass_str : 'parent.' + xss + '.updateBar(100, "");',
  ctrl_re  : '<script type="text/javascript">'
);

if (!exploited)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Liferay Portal", build_url(qs:dir + cgi, port:port));
