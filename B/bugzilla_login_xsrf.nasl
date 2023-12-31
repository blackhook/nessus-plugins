#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74107);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-1517");
  script_bugtraq_id(66984);

  script_name(english:"Bugzilla 2.0 < 4.4.3 / 4.5.3 Login Form XSRF");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that suffers from a
cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla installed on the
remote host is after version 2.0 but prior to 4.4.3 / 4.5.3. It is,
therefore, affected by a cross-site request forgery vulnerability.

The vulnerability exists with the login form and could allow a remote
attacker to cause a user to login using the attacker's credentials,
alerting the attacker of any bugs the user submits.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/4.0.11/");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=713926");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Bugzilla 4.4.3 / 4.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bugzilla_detect.nasl");
  script_require_keys("installed_sw/Bugzilla", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install["path"];
version = install["version"];

install_loc = build_url(port:port, qs:dir + "/query.cgi");

if (version =~ "^4($|[^0-9.])")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

# Versions less than 4.4.3 / 4.5.3 are vulnerable
if (
  version =~ "^[23]\." ||
  version =~ "^4\.[0-3]([^0-9]|$)" ||
  version =~ "^4\.(4|4\.[0-2])([^0-9.]|$)" ||
  version =~ "^4\.(5|5\.[12])([^0-9.]|$)"
)
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 4.4.3 / 4.5.3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
