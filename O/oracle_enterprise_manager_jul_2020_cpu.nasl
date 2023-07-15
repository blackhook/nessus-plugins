#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138555);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-11776",
    "CVE-2019-0227",
    "CVE-2019-12415",
    "CVE-2020-2982",
    "CVE-2020-9546"
  );
  script_bugtraq_id(105125, 107867);
  script_xref(name:"IAVA", value:"2020-A-0326");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 13.3.0.0, 13.4.0.0, and 12.1.0.5 versions of Enterprise Manager Base Platform installed on the remote host are
affected by multiple vulnerabilities as referenced in the July 2020 CPU advisory.

  - Vulnerability in the Enterprise Manager Base Platform
    product of Oracle Enterprise Manager (component:
    Enterprise Manager Install (jackson-databind)).
    Supported versions that are affected are 13.3.0.0 and
    13.4.0.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to
    compromise Enterprise Manager Base Platform. Successful
    attacks of this vulnerability can result in takeover of
    Enterprise Manager Base Platform. CVSS 3.1 Base Score
    9.8 (Confidentiality, Integrity and Availability
    impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
    (CVE-2020-9546)

  - Vulnerability in the Enterprise Manager Base Platform
    product of Oracle Enterprise Manager (component:
    Reporting Framework (Apache Struts 2)). Supported
    versions that are affected are 13.3.0.0 and 13.4.0.0.
    Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via HTTP to
    compromise Enterprise Manager Base Platform. Successful
    attacks of this vulnerability can result in takeover of
    Enterprise Manager Base Platform. CVSS 3.1 Base Score
    8.1 (Confidentiality, Integrity and Availability
    impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).
    (CVE-2018-11776)

  - Vulnerability in the Enterprise Manager Base Platform
    product of Oracle Enterprise Manager (component:
    Application Service Level Mgmt (Apache Axis)). Supported
    versions that are affected are 12.1.0.5 and 13.3.0.0.
    Difficult to exploit vulnerability allows
    unauthenticated attacker with access to the physical
    communication segment attached to the hardware where the
    Enterprise Manager Base Platform executes to compromise
    Enterprise Manager Base Platform. Successful attacks of
    this vulnerability can result in takeover of Enterprise
    Manager Base Platform. CVSS 3.1 Base Score 7.5
    (Confidentiality, Integrity and Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).
    (CVE-2019-0227)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11776");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-9546");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Struts 2 Multiple Tags Result Namespace Handling RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts 2 Namespace Redirect OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include('vcf.inc');

app_name = 'Oracle Enterprise Manager Cloud Control';

app_info = vcf::get_app_info(app:app_name);

# affected versions and patches 
# (mapping added in oracle_enterprise_manager_installed.nbin)
#
# 13.4.0
# 31459685 -> 13.4.0.4
#
# 13.3.0.0
# 31250768 -> 13.3.0.0.200714
#
# 12.1.0.5
# 31250739 -> 12.1.0.5.200714
 
constraints = [
  { 'min_version' : '13.4.0.0', 'fixed_version' : '13.4.0.4', 'fixed_display': '13.4.0.4 (Patch 31459685)'},
  { 'min_version' : '13.3.0.0', 'fixed_version' : '13.3.0.0.200714', 'fixed_display': '13.3.0.0.200714 (Patch 31250768)'},
  { 'min_version' : '12.1.0.5', 'fixed_version' : '12.1.0.5.200714', 'fixed_display': '12.1.0.5.200714 (Patch 31250739)' }
];
 
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

