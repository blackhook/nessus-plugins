#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92355);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Drupal RESTWS Module Page Callback RCE");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote web server is affected by
a remote code execution vulnerability in the bundled RESTful Web
services (RESTWS) module due to a flaw in how default page callbacks
for Drupal entities are altered when handling specially crafted
requests. An unauthenticated, remote attacker can exploit this, via a
crafted request, to execute arbitrary PHP code.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/2765567");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/restws");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RESTful Web Services 7.x-1.7 / 7.x-2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:restful_web_services_project:restws");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2022 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

url = "/file/0/phpinfo";
res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

if("<title>phpinfo()</title>" >< res[2])
{
  output = strstr(res[2], ">PHP Version");
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    generic     : TRUE,
    request     : make_list(install_url + url),
    output      : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
