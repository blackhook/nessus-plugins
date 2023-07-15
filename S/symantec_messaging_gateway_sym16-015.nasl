#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93653);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-5309", "CVE-2016-5310", "CVE-2016-5312");
  script_bugtraq_id(92866, 92868, 93148);

  script_name(english:"Symantec Messaging Gateway 10.x < 10.6.2 Multiple Vulnerabilities (SYM16-015) (SYM16-016)");
  script_summary(english:"Checks the Symantec Messaging Gateway version number.");

  script_set_attribute(attribute:"synopsis", value:
"A messaging security application running on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec Messaging
Gateway (SMG) running on the remote host is 10.x prior to 10.6.2. It
is, therefore, affected by multiple vulnerabilities :

  - A denial of service vulnerability exists in the
    decomposer engine due to an out-of-bounds read error
    that occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5309)

  - A denial of service vulnerability exists in the
    decomposer engine due to memory corruption issue that
    occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5310)

  - An information disclosure vulnerability exists in the
    charting component in the control center due to improper
    sanitization of user-supplied input submitted for
    charting requests. An authenticated, remote attacker can
    exploit this, via a directory traversal attack, to
    disclose arbitrary files or directory contents.
    (CVE-2016-5312)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://support.symantec.com/en_US/article.SYMSA1379.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0df20c4e");
  # https://support.symantec.com/en_US/article.SYMSA1380.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d959567");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Messaging Gateway (SMG) version 10.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5312");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Symantec Messaging Gateway 10.6.1 File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# Detection does not provide anything more detailed
# than 'x.y.z'.

if (
  install['version'] =~ "^10\.[0-5]($|[^0-9])" ||
  install['version'] =~ "^10\.6\.[01]($|[^0-9])"
)
{
  report =
    '\n  URL               : ' + base_url +
    '\n  Installed version : ' + install['version'] +
    '\n  Fixed version     : 10.6.2\n';

  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Messaging Gateway', base_url, install['version']);
