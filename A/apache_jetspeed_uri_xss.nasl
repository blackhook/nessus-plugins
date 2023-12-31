#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90247);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-0712");

  script_name(english:"Apache Jetspeed Portal URI Path Reflected XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Apache Jetspeed application running on the remote host is affected
by a reflected cross-site scripting (XSS) vulnerability in the /portal
script due to improper validation of URI path input before returning
it to the users. An unauthenticated, remote attacker can exploit this,
via a specially crafted request, to execute arbitrary script code in a
user's browser session.

Note that Apache Jetspeed is reported to be affected by other
vulnerabilities as well; however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://portals.apache.org/jetspeed-2/security-reports.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Jetspeed version 2.3.1 when it becomes available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0712");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:jetspeed");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_jetspeed_detect.nbin");
  script_require_keys("installed_sw/Apache Jetspeed");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Apache Jetspeed";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# needed to init session properly
http_send_recv3(method:'GET', port:port, item:dir + "/portal", exit_on_fail:TRUE);

exploit = test_cgi_xss(port    : port,
                       dirs    : make_list(dir),
                       cgi     : "/portal",
                       qs      : "/foo%22%20onmouseover=%22alert%28'xss'%29?URL=foo/bar",
                       ctrl_re : 'class="portlet jetspeed"',
                       pass_re : '<a\\s*href="[^"]+"\\s*onmouseover="alert\\(\'xss\'\\)"',
                       no_qm   : TRUE);

if (!exploit)
 audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
