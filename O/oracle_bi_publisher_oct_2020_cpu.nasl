#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142372);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-11358",
    "CVE-2020-14780",
    "CVE-2020-14784",
    "CVE-2020-14842",
    "CVE-2020-14879",
    "CVE-2020-14880"
  );
  script_xref(name:"IAVA", value:"2020-A-0478");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher or Oracle Analytics Server 5.5 running on the remote host is
11.1.1.9.x prior to 11.1.1.9.201020, 12.2.1.3.x prior to 12.2.1.3.201020, 12.2.1.4.x prior to 12.2.1.4.201020, or
12.2.5.5.x (OAS 5.5) prior to 12.2.5.5.201012. It is, therefore, affected by multiple vulnerabilities as noted in
the October 2020 Critical Patch Update advisory:

  - An unspecified vulnerability exists in the BI Publisher product of Oracle Fusion Middleware (component: BI
    Publisher Security (jQuery)). An unauthenticated, remote attacker can exploit this, via HTTP, which can
    result in unauthorized update, insert or delete access to some of BI Publisher accessible data as well as
    unauthorized read access to a subset of BI Publisher accessible data. (CVE-2019-11358)

  - An unspecified vulnerability exists in the BI Publisher product of Oracle Fusion Middleware (component: BI
    Publisher Security). An unauthenticated, remote attacker can exploit this, via HTTP, which can result in
    unauthorized access to critical data or complete access to all BI Publisher accessible data as well as
    unauthorized update, insert or delete access to some of BI Publisher accessible data. (CVE-2020-14780,
    CVE-2020-14842)
    
  - An unspecified vulnerability exists in the Oracle BI Publisher product of Oracle Fusion Middleware
    (component: Mobile Service). An unauthenticated, remote attacker can exploit this, via HTTP, which can
    result in unauthorized access to critical data or complete access to all Oracle BI Publisher accessible
    data as well as unauthorized update, insert or delete access to some of Oracle BI Publisher accessible
    data. (CVE-2020-14784)

  - An unspecified vulnerability exists in the BI Publisher product of Oracle Fusion Middleware (component:
    E-Business Suite - XDO). An unauthenticated, remote attacker can exploit this, via HTTP, which can result
    in unauthorized access to critical data or complete access to all BI Publisher accessible data as well as
    unauthorized update, insert or delete access to some of BI Publisher accessible data. (CVE-2020-14879,
    CVE-2020-14880)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14879");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::get_app_info(app:'Oracle Business Intelligence Publisher');

constraints = [
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.201020', 'patch': '31896352', 'bundle': '31943269'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.201020', 'patch': '31690029', 'bundle': '31690029'},
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.201020', 'patch': '31690037', 'bundle': '31690037'},
  # Oracle Analytics Server 5.5
  {'min_version': '12.2.5.5', 'fixed_version': '12.2.5.5.201012', 'patch': '32003790', 'bundle': '32003790'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);
