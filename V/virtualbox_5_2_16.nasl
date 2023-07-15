#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111208);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/05");

  script_cve_id(
    "CVE-2018-3005",
    "CVE-2018-3055",
    "CVE-2018-3085",
    "CVE-2018-3086",
    "CVE-2018-3087",
    "CVE-2018-3088",
    "CVE-2018-3089",
    "CVE-2018-3090",
    "CVE-2018-3091"
  );
  script_bugtraq_id(
    103144,
    103518,
    104207,
    104764
  );

  script_name(english:"Oracle VM VirtualBox < 5.2.16 Multiple Vulnerabilities (July 2018 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox running on the remote host is
5.2.x prior to 5.2.16. It is, therefore, affected by multiple
vulnerabilities as noted in the April 2018 Critical Patch Update
advisory : 

  - An unspecified vulnerability in the Oracle VM VirtualBox
    component of Oracle Virtualization in the Core
    subcomponent could allow an unauthenticated, remote
    attacker with logon to the infrastructure where Oracle
    VM VirtualBox executes to compromise Oracle VM
    VirtualBox. (CVE-2018-3005, CVE-2018-3085, CVE-2018-3086
    CVE-2018-3087, CVE-2018-3088, CVE-2018-3089,
    CVE-2018-3090, CVE-2018-3091, CVE-2018-3055)

Please consult the CVRF details for the applicable CVEs for
additional information.

Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4c9a415");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.2.16 or later as
referenced in the July 2018 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3085");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"agent", value:"all");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
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

# Affected :
# 5.2.x < 5.2.16
if (ver =~ '^5\\.2' && ver_compare(ver:ver, fix:'5.2.16', strict:FALSE) < 0) fix = '5.2.16';
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
