#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145267);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2016-1000031", "CVE-2020-11973");
  script_xref(name:"IAVA", value:"2021-A-0032");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Jan 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 13.3.0.0, 13.4.0.0, and 13.2.1.0 versions of Enterprise Manager Base Platform installed on the remote host are
affected by multiple vulnerabilities as referenced in the January 2021 CPU advisory.

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component:
    Reporting Framework (Apache Camel)). Supported versions that are affected are 13.3.0.0 and 13.4.0.0.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Enterprise Manager Base Platform. Successful attacks of this vulnerability can result in
    takeover of Enterprise Manager Base Platform.

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component:
    Reporting Framework (Apache Commons FileUpload)). Supported versions that are affected are 13.3.0.0 and
    13.4.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Enterprise Manager Base Platform. Successful attacks of this vulnerability can result in
    takeover of Enterprise Manager Base Platform.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11973");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin", "oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Oracle Enterprise Manager Cloud Control');

## IMPORTANT: See https://support.oracle.com/epmos/faces/DocumentDisplay?id=2725756.1
## CVE-2016-1000031, CVE-2020-11973 require Oracle Business Intelligence BUNDLE PATCH 12.2.1.3.200114 Patch 30499022 or later
## they only apply to 13.3 and 13.4 though

if (app_info.version =~ "^13\.[34]")
{
  ## now retrieve and check BI patches
  bi_app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

  constraints = [
    { 'min_version' : '12.2.1.3', 'fixed_version' : '12.2.1.3.200114', 'fixed_display': '12.2.1.3.200114 (Oracle BI)' }
  ];

  # checking against the BI version, as OBI BUNDLE PATCH 12.2.1.3.200114 Patch 30499022 or later is requird
  vcf::check_version_and_report(app_info:bi_app_info, constraints:constraints, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_info.version);


