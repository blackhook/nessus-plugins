#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88904);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2016-82000");

  script_name(english:"Tenable Nessus < 6.5.5 Host Details Scan Results XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Nessus installation is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Tenable Nessus application running on
the remote host is prior to 6.5.5. It is, therefore, affected by a
cross-site scripting (XSS) vulnerability in the Host Details section
due to improper sanitization of user-supplied input. An
unauthenticated, remote attacker can exploit this, via importing a
malicious file or by scanning a malicious host that returns JavaScript
instead of a hostname, to introduce and store JavaScript in the scan
results, which can be later executed in the context of the user
viewing the results.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2016-02");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 6.5.5 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-82000");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/23");

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

var ver_ui = install['version'];
if (ver_compare(ver:ver_ui, fix:'2.0.0', strict:FALSE) < 0)
  audit(AUDIT_LISTEN_NOT_VULN, "Nessus", port, ver_ui);

var version = install['version'];

var fix = '6.5.5';
var report = '';

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port: port, severity:SECURITY_NOTE, extra: report, xss:TRUE);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Nessus", port, version);