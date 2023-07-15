#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97193);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2016-9259");

  script_name(english:"Tenable Nessus 6.8.x and 6.9.x < 6.9.1 Stored XSS (TNS-2016-17)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a stored
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Tenable Nessus
application running on the remote host is 6.8.x or 6.9.x prior to
6.9.1. It is, therefore, affected by a stored cross-site scripting
(XSS) vulnerability due to improper validation of user-supplied input.
An authenticated, remote attacker can exploit this, via a specially
crafted request, to execute arbitrary script code in a user's browser
session.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2016-17");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 6.9.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9259");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");
  script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include("http.inc");
include("install_func.inc");

var app = "Tenable Nessus";
get_install_count(app_name:app, exit_if_zero:TRUE);
var port = get_http_port(default:8834);

var install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

var version = install['version'];

var fix = '6.9.1';

# Affected versions:
# 6.8 / 6.8.1 / 6.8.2 / 6.9
var order, report;

if (version =~ "^6\.[89]" && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  order = make_list('Installed version', 'Fixed version');
  report = make_array(
    order[0], version,
    order[1], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE, xss:TRUE);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Nessus", port, version);