#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178010);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2022-42003", "CVE-2022-45047", "CVE-2023-21894");

  script_name(english:"Oracle Global Lifecycle Management (OPatch) (Jan 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The installation of Oracle Global Lifecycle Management (OPatch) installed on the remote host is affected by multiple
vulnerabilities as referenced in the January 2023 CPU advisory.

  - Vulnerability in the Oracle Global Lifecycle Management NextGen OUI Framework product of Oracle Fusion
    Middleware (component: NextGen Installer issues (jackson-databind)). Supported versions that are affected
    are Prior to 13.9.4.2.11. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via HTTP to compromise Oracle Global Lifecycle Management NextGen OUI Framework. Successful attacks
    of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of Oracle Global Lifecycle Management NextGen OUI Framework. (CVE-2022-42003)

  - Vulnerability in the Oracle Global Lifecycle Management NextGen OUI Framework product of Oracle Fusion
    Middleware (component: NextGen Installer issues (Apache Mina SSHD)). Supported versions that are affected
    are Prior to 13.9.4.2.11. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via HTTP to compromise Oracle Global Lifecycle Management NextGen OUI Framework. Successful attacks
    of this vulnerability can result in takeover of Oracle Global Lifecycle Management NextGen OUI Framework.
    (CVE-2022-45047)

  - Vulnerability in the Oracle Global Lifecycle Management NextGen OUI Framework product of Oracle Fusion
    Middleware (component: NextGen Installer issues). Supported versions that are affected are Prior to
    13.9.4.2.11. Easily exploitable vulnerability allows low privileged attacker with logon to the
    infrastructure where Oracle Global Lifecycle Management NextGen OUI Framework executes to compromise
    Oracle Global Lifecycle Management NextGen OUI Framework. Successful attacks require human interaction
    from a person other than the attacker. Successful attacks of this vulnerability can result in takeover of
    Oracle Global Lifecycle Management NextGen OUI Framework. (CVE-2023-21894)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45047");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:global_lifecycle_management_opatch");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_opatch_installed.nbin");
  script_require_keys("installed_sw/Oracle OPatch");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle OPatch');

# OUI NextGen OPatch is version 13.x
var constraints = [
  { 'min_version': '13.0.0.0', 'fixed_version': '13.9.4.2.11', 'fixed_display': '13.9.4.2.11 (Patch 28186730)'}
];

vcf::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);
