#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77158);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_bugtraq_id(67618);

  script_name(english:"Atlassian Crucible 3.x < 3.0.4 / 3.1.7 / 3.2.5 / 3.3.4 / 3.4.4 Administrator Password Reset");
  script_summary(english:"Checks the version of Crucible.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Crucible installed on the remote host is
potentially affected by an administrator password reset flaw.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installation of Atlassian
Crucible running on the remote host is potentially affected by a flaw
in which a remote, unauthenticated user is able to set the 'admin'
user for Crucible to an arbitrary value. This can allow an attacker to
gain administrative access to the application.");
  script_set_attribute(attribute:"solution", value:"Upgrade to Crucible 3.0.4 / 3.1.7 / 3.2.5 / 3.3.4 / 3.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
   # https://confluence.atlassian.com/crucible/fisheye-and-crucible-security-advisory-2014-05-21-597557693.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09a8ff3e");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CRUC-6810");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:crucible");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("crucible_detect.nasl");
  script_require_keys("installed_sw/crucible", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8060);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

port = get_http_port(default:8060);
app = "Crucible";
app_name = tolower(app);

get_install_count(app_name:app_name, exit_if_zero:TRUE);

install = get_single_install(
  app_name : app_name,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = "";
vuln = 0;

# Only 3.x versions are affected
if (ver =~ "^3\.0([^0-9]|$)")
{
  fix = "3.0.4";
  vuln = ver_compare(ver:ver, fix:fix, strict:FALSE);
}
else if (ver =~ "^3\.1([^0-9]|$)")
{
  fix = "3.1.7";
  vuln = ver_compare(ver:ver, fix:fix, strict:FALSE);
}
else if (ver =~ "^3\.2([^0-9]|$)")
{
  fix = "3.2.5";
  vuln = ver_compare(ver:ver, fix:fix, strict:FALSE);
}
else if (ver =~ "^3\.3([^0-9]|$)")
{
  fix = "3.3.4";
  vuln = ver_compare(ver:ver, fix:fix, strict:FALSE);
}
else if (ver =~ "^3\.4([^0-9]|$)")
{
  fix = "3.4.4";
  vuln = ver_compare(ver:ver, fix:fix, strict:FALSE);
}

if (vuln >= 0) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
exit(0);
