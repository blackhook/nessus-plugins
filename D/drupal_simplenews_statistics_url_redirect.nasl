#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42254);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-3784");
  script_bugtraq_id(36790);
  script_xref(name:"SECUNIA", value:"37128");

  script_name(english:"Drupal SA-CONTRIB-2009-080: Simplenews Statistics Open Redirect");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by an
open redirect vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote web server includes the
third-party Simplenews Statistics module, which provides newsletter
statistics such as open and click-through rates.

The version of Simplenews Statistics installed contains an open
redirect, which can be used in a phishing attack to trick users into
visiting malicious sites.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/611002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Simplenews Statistics version 6.x-2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-3784");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sjoerd_arendsen:simplenews_statistics");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# Try to exploit the issue.
redirect = "http://www.example.com/";
url = '/simplenews/statistics/click?url='+redirect;

res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['$code'])) code = 0;
else code = hdrs['$code'];

if (isnull(hdrs['location'])) location = "";
else location = hdrs['location'];

# There's a problem if ...
if (
  # we're redirected and ...
  code == 302 &&
  # it's to the location we specified
  redirect == location
)
{
  output = res[0] + '\n' + res[1];

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    generic     : TRUE,
    request     : make_list(install_url + url),
    output      : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
