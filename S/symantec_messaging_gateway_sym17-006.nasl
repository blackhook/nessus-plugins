#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(102528);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-6327", "CVE-2017-6328");
  script_bugtraq_id(100135, 100136);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");

  script_name(english:"Symantec Messaging Gateway 10.x < 10.6.3-267 Multiple Vulnerabilities (SYM17-006)");

  script_set_attribute(attribute:"synopsis", value:
"A messaging security application running on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec Messaging
Gateway (SMG) running on the remote host is 10.x prior to 10.6.3-267.
It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists due to a failure to properly sanitize
    user-supplied input. An authenticated, remote attacker can exploit
    this to execute arbitrary commands. (CVE-2017-6327)

  - A cross site request Forgery (CSRF) vulnerability exists as HTTP
    requests to certain pages do not require multiple steps, explicit
    confirmation, or a unique token when performing certain sensitive
    actions. (CVE-2017-6328)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://support.symantec.com/en_US/article.SYMSA1411.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d53eb37");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Messaging Gateway (SMG) version 10.6.3-267 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6328");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Symantec Messaging Gateway RestoreAction.performRestore() RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_messaging_gateway_detect.nasl");
  script_require_keys("www/sym_msg_gateway");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:'sym_msg_gateway', exit_if_zero:TRUE);

port = get_http_port(default:443);
install = get_single_install(app_name:'sym_msg_gateway', port:port);
base_url = build_url(qs:install['dir'], port:port);

if (install['version'] == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Symantec Messaging Gateway', base_url);
if (install['version'] !~ "^10(\.|$)")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Messaging Gateway', base_url, install['version']);
if (install['version'] =~ "^10(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, 'Symantec Messaging Gateway', port, install['version']);

# Detection does not provide anything more detailed than 'x.y.z'
if (install['version'] == "10.6.3" && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if (
  install['version'] =~ "^10\.[0-5]($|[^0-9])" ||
  install['version'] =~ "^10\.6\.[0-3]($|[^0-9])"
)
{
  report =
    '\n  URL               : ' + base_url +
    '\n  Installed version : ' + install['version'] +
    '\n  Fixed version     : 10.6.3-267\n';

  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report, xsrf:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Messaging Gateway', base_url, install['version']);
