#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81181);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(66011);

  script_name(english:"Atmail Webmail 7.x < 7.2.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Atmail Webmail installed on the remote
host is 7.x prior to 7.2.2. It is, therefore, affected by the
following vulnerabilities :

  - An unspecified input validation error exists that allows
    cross-site scripting attacks (XSS).

  - An unspecified input validation error exists that allows
    cross-site request forgery attacks (XSRF).");
  # https://web.archive.org/web/20151003223402/https://www.atmail.com/blog/atmail-722-out
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46fb5feb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atmail Webmail 7.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atmail:atmail");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("atmail_webmail_detect.nasl");
  script_require_keys("installed_sw/atmail_webmail");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:'atmail_webmail', port:port, exit_on_fail:TRUE);

dir = install['dir'];
display_version = install['ver'];
# Get normalized version for check
kb_dir = str_replace(string:dir, find:"/", replace:"\");
version = get_kb_item_or_exit('www/'+port+'/atmail_webmail_normalized_ver/'+kb_dir+'/'+display_version);
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER || isnull(version))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, "Atmail Webmail", install_url);

if (version =~ "^7(\.2)?$")
  audit(AUDIT_VER_NOT_GRANULAR, "Atmail Webmail", port, version);
if (version !~ "^7\.")
  audit(AUDIT_WEB_APP_NOT_INST, "Atmail Webmail 7.x", port);

if (ver_compare(ver:version, fix:'7.2.2', strict:FALSE) < 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version + ' ('+display_version+')' +
      '\n  Fixed version     : 7.2.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Atmail Webmail", install_url, display_version);
