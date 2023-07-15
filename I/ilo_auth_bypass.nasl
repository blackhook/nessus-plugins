#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(102803);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_cve_id("CVE-2017-12542");
  script_bugtraq_id(100467);

  script_name(english:"HP iLO 4 <= 2.52 RCE");
  script_summary(english:"Checks version of HP Integrated Lights-Out 4 (iLO 4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out 4 (iLO 4) server is vulnerable
to multiple unspecified flaws that allow a remote attacker to bypass
authentication and execute code.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote HP Integrated Lights-Out 4
(iLO 4) server is affected by multiple unspecified flaws that allow a
remote attacker to bypass authentication and execute arbitrary code.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=hpesbhf03769en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a40b909a");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP Integrated Lights-Out 4 (iLO 4) firmware version 2.53.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12542");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_4_firmware");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ilo_detect.nasl");
  script_require_keys("www/ilo", "ilo/generation", "ilo/firmware");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('http.inc');
include('misc_func.inc');
include('webapp_func.inc');
include('vcf_extras.inc');

# Each generation has its own series of firmware version numbers.
var generation = get_kb_item_or_exit("ilo/generation");

# The version is tied to the firmware and not specific to the web interface.
var version = get_kb_item_or_exit("ilo/firmware");
var port = get_http_port(default:80, embedded:TRUE);

var install = get_install_from_kb(
  appname      : "ilo",
  port         : port,
  exit_on_fail : TRUE
);
var install_url = build_url(port:port, qs:install["dir"]);
vcf::ilo::check_superdome(audit:TRUE);

# Firmware is unique to the generation of iLO.
if (generation != 4) audit(AUDIT_WEB_APP_NOT_AFFECTED, "iLO " + generation, install_url, version);

var cutoff_version = "2.52";
if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  report =
    '\n  URL              : ' + install_url +
    '\n  Generation       : ' + generation +
    '\n  Firmware version : ' + version +
    '\n  Fixed version    : 2.53' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "iLO " + generation, install_url, version);
