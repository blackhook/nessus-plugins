#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106947);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-18084");
  script_bugtraq_id(103064);

  script_name(english:"Atlassian Confluence < 6.3.4 usermacros Reflected XSS (CVE-2017-18084)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a
reflected cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Atlassian
Confluence application running on the remote host is prior to 6.3.4.
It is, therefore, affected by a reflected cross-site scripting
vulnerability in the usermacros resource.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-54904");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 6.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl");
  script_require_keys("www/confluence", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080, 8090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8090);

install = get_install_from_kb(
  appname      :'confluence',
  port         :port,
  exit_on_fail :TRUE
);

dir     = install['dir'];
version = install['ver'];
install_url = build_url(port:port, qs:dir);
fix_ver = '6.3.4';

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Confluence", install_url);
if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (version =~ '^6(\\.3)?$') audit(AUDIT_VER_NOT_GRANULAR, "Confluence", port, version);

if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_ver +
    '\n';
  security_report_v4(severity:SECURITY_NOTE, port:port, extra:report, xss:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Confluence", install_url, version);
