#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156898);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/25");

  script_cve_id("CVE-2022-21392");
  script_xref(name:"IAVA", value:"2022-A-0036");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Jan 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The 13.4.0.0 and 13.5.0.0 versions of Enterprise Manager Base Platform installed on the remote host are affected by a
vulnerability as referenced in the January 2022 CPU advisory.

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component:
    Policy Framework). Supported versions that are affected are 13.4.0.0 and 13.5.0.0. Easily exploitable
    vulnerability allows low privileged attacker with network access via HTTP to compromise Enterprise Manager
    Base Platform. Successful attacks of this vulnerability can result in unauthorized access to critical data
    or complete access to all Enterprise Manager Base Platform accessible data as well as unauthorized update,
    insert or delete access to some of Enterprise Manager Base Platform accessible data. CVSS 3.1 Base Score
    7.1 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N).
    (CVE-2022-21392)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_agent_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Agent");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");
include("install_func.inc");

var os = get_kb_item_or_exit('Host/OS');

if (tolower(os) =~ 'windows')
{
    audit(AUDIT_OS_NOT,'affected');
}

var product = 'Oracle Enterprise Manager Agent';
var install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);
var version = install['version'];
var emchome = install['path'];

var patch = '33565758';

if (version != '13.4.0.0.0' && version != '13.5.0.0.0')
  audit(AUDIT_INST_PATH_NOT_VULN, product, version, emchome);

var patchesinstalled = find_patches_in_ohomes(ohomes:make_list(emchome));

var patched = FALSE;

var patchid;

if (!isnull(patchesinstalled))
{
  foreach patchid (keys(patchesinstalled[emchome]))
  {
    if (patchid == patch) {
      patched = TRUE;
      break;
    }
  }
}

if (patched) audit(AUDIT_INST_PATH_NOT_VULN, product, version, emchome);

var report =
  '\n  Product       : ' + product +
  '\n  Version       : ' + version +
  '\n  Path          : ' + emchome +
  '\n  Missing patch : ' + patch +
  '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
