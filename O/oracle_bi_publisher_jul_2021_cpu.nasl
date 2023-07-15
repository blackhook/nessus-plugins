#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152027);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-2391",
    "CVE-2021-2392",
    "CVE-2021-2396",
    "CVE-2021-2400",
    "CVE-2021-2401"
  );
  script_xref(name:"IAVA", value:"2021-A-0326");

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (Jul 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher or Oracle Analytics Server 5.5 running on the remote host is
11.1.1.9.x prior to 11.1.1.9.210720, 12.2.1.3.x prior to 12.2.1.3.210405, 12.2.1.4.x prior to 12.2.1.4.210402, or
12.2.5.5.x (OAS 5.5) prior to 12.2.5.5.210331. It is, therefore, affected by multiple vulnerabilities as noted in
the July 2021 Critical Patch Update advisory, including the following:

  - Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: Scheduler). Easily
    exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle
    BI Publisher. Successful attacks of this vulnerability can result in takeover of Oracle BI Publisher.
    (CVE-2021-2392)

  - Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: E-Business Suite - XDO).
    Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle
    BI Publisher. Successful attacks of this vulnerability can result in takeover of Oracle BI Publisher.
    (CVE-2021-2396)

  - Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: E-Business Suite - XDO).
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle
    BI Publisher. Successful attacks of this vulnerability can result in unauthorized access to critical data or
    complete access to all Oracle BI Publisher accessible data.  (CVE-2021-2400)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuJul2021.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuJul2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

var constraints = [
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.210720', 'patch': '33032067', 'bundle': '33032067'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.210714', 'patch': '33115114', 'bundle': '33115114'},
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.210714', 'patch': '33115118', 'bundle': '33115118'},
  # Oracle Analytics Server 5.5
  {'min_version': '12.2.5.5', 'fixed_version': '12.2.5.5.210709', 'patch': '33098627', 'bundle': '33098627'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);
