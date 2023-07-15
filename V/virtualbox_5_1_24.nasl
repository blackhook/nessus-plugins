#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101818);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-10129",
    "CVE-2017-10187",
    "CVE-2017-10204",
    "CVE-2017-10209",
    "CVE-2017-10210",
    "CVE-2017-10233",
    "CVE-2017-10235",
    "CVE-2017-10236",
    "CVE-2017-10237",
    "CVE-2017-10238",
    "CVE-2017-10239",
    "CVE-2017-10240",
    "CVE-2017-10241",
    "CVE-2017-10242"
  );
  script_bugtraq_id(
    99631,
    99638,
    99640,
    99642,
    99645,
    99667,
    99668,
    99681,
    99683,
    99687,
    99689,
    99705,
    99709,
    99711
  );

  script_name(english:"Oracle VM VirtualBox 5.1.x < 5.1.24 (July 2017 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox installed on the remote host is
5.1.x prior to 5.1.24. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple unspecified vulnerabilities exist in the Core
    component that allow a local attacker to have an impact
    on confidentiality, integrity, and availability.
    (CVE-2017-10129, CVE-2017-10204, CVE-2017-10210,
    CVE-2017-10236, CVE-2017-10237, CVE-2017-10238,
    CVE-2017-10239, CVE-2017-10240, CVE-2017-10241,
    CVE-2017-10242)

  - Multiple unspecified vulnerabilities exist in the Core
    component that allow a local attacker to have an impact
    on integrity and availability. (CVE-2017-10187,
    CVE-2017-10233, CVE-2017-10235)

  - An unspecified vulnerability exists in the Core
    component that allows a local attacker to have an impact
    on confidentiality and availability. (CVE-2017-10209)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76f5def7");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3236622.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efb80e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.1.24 or later as
referenced in the July 2017 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10242");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
# 5.1.x < 5.1.24
if (ver =~ '^5\\.1' && ver_compare(ver:ver, fix:'5.1.24', strict:FALSE) < 0) fix = '5.1.24';
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
