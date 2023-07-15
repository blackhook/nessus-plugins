#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106104);
  script_version("1.16");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2017-3735",
    "CVE-2017-3736",
    "CVE-2017-5715",
    "CVE-2018-2685",
    "CVE-2018-2686",
    "CVE-2018-2687",
    "CVE-2018-2688",
    "CVE-2018-2689",
    "CVE-2018-2690",
    "CVE-2018-2694",
    "CVE-2018-2698"
  );
  script_bugtraq_id(100515, 101666, 102376);
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"Oracle VM VirtualBox 5.1.x < 5.1.32 / 5.2.x < 5.2.6 (January 2018 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox running on the remote host is
5.1.x prior to 5.1.32 or 5.2.x prior to 5.2.6. It is, therefore,
affected by multiple vulnerabilities as noted in the January 2018
Critical Patch Update advisory. Please consult the CVRF details
for the applicable CVEs for additional information.

Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae82f1b1");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.1.32 / 5.2.6 or later as
referenced in the January 2018 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3735");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("virtualbox_installed.nasl", "macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/Oracle VM VirtualBox", "installed_sw/VirtualBox");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app  = NULL;
apps = make_list('Oracle VM VirtualBox', 'VirtualBox');

foreach app (apps)
{
  if (get_install_count(app_name:app)) break;
  else app = NULL;
}

if (isnull(app)) audit(AUDIT_NOT_INST, 'Oracle VM VirtualBox');

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver  = install['version'];
path = install['path'];


# 5.1.x < 5.1.32
if (ver =~ '^5\\.1' && ver_compare(ver:ver, fix:'5.1.32', strict:FALSE) < 0) fix = '5.1.32';
# 5.2.x < 5.2.6
else if (ver =~ '^5\\.2' && ver_compare(ver:ver, fix:'5.2.6', strict:FALSE) < 0) fix = '5.2.6';
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = 0;
if (app == 'Oracle VM VirtualBox')
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
exit(0);

