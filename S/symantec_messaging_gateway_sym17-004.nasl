#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101158);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-6324", "CVE-2017-6325", "CVE-2017-6326");
  script_bugtraq_id(98889, 98890, 98893);
  script_xref(name:"EDB-ID", value:"42251");

  script_name(english:"Symantec Messaging Gateway 10.x < 10.6.3-266 Multiple Vulnerabilities (SYM17-004)");
  script_summary(english:"Checks the Symantec Messaging Gateway version number.");

  script_set_attribute(attribute:"synopsis", value:
"A messaging security application running on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec Messaging
Gateway (SMG) running on the remote host is 10.x prior to 10.6.3-266.
It is, therefore, affected by multiple vulnerabilities :

  - A security feature bypass vulnerability exists when
    handling email attachments involving malformed or
    corrupted Word files containing macros. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted email, to bypass the 'disarm'
    functionality even though it has been enabled by the
    administrator. (CVE-2017-6324)

  - A local file inclusion vulnerability exists due to a
    failure to properly sanitize user-supplied input when
    building a path to executable code. An authenticated,
    remote attacker can exploit this, via a specially
    crafted request, to include arbitrary files for
    execution, provided they are already present on the
    targeted host. (CVE-2017-6325)

  - An unspecified flaw exists that allows an authenticated,
    remote attacker to execute arbitrary code.
    (CVE-2017-6326)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://support.symantec.com/en_US/article.SYMSA1406.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3185d81e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Messaging Gateway (SMG) version 10.6.3-266 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6326");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec Messaging Gateway Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    '\n  Fixed version     : 10.6.3-266\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Messaging Gateway', base_url, install['version']);
