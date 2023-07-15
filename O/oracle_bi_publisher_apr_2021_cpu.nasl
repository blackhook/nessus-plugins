#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148980);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-0221",
    "CVE-2020-1971",
    "CVE-2020-9480",
    "CVE-2020-11022",
    "CVE-2021-2152",
    "CVE-2021-2191"
  );
  script_xref(name:"IAVA", value:"2021-A-0196");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher or Oracle Analytics Server 5.5 running on the remote host is
11.1.1.9.x prior to 11.1.1.9.210215, 12.2.1.3.x prior to 12.2.1.3.210405, 12.2.1.4.x prior to 12.2.1.4.210402, or
12.2.5.5.x (OAS 5.5) prior to 12.2.5.5.210331. It is, therefore, affected by multiple vulnerabilities as noted in
the April 2021 Critical Patch Update advisory, including the following:

  - An unspecified vulnerability exists in the Analytics Server component of Oracle BI Enterprise Edition
    subcomponent Apache Spark. An unauthenticated, remote attacker can exploit this, via HTTP, to take over
    Oracle BI Enterprise Edition. (CVE-2020-9480)

  - A denial of service vulnerability exists in the BI Platform Security component of Oracle BI Enterprise
    Edition subcomponent OpenSSL. An unauthenticated, remote attacker can exploit this, via HTTPS, to hang or
    repeatedly crash the product. (CVE-2020-1971)

  - An unspecified vulnerability exists in the BI Platform Security component of Oracle BI Enterprise Edition
    subcomponent Apache Tomcat.  An unauthenticated, remote attacker can exploit this, via HTTP, to result in
    unauthorized update, insert, or delete access to some of Oracle BI accessible data, as well as
    unauthorized read access to a subset of Oracle BI accessible data. (CVE-2019-0221)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9480");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/26");

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
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.210215', 'patch': '32508654', 'bundle': '32744336'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.210405', 'patch': '32726874', 'bundle': '32726874'},
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.210402', 'patch': '32718479', 'bundle': '32718479'},
  # Oracle Analytics Server 5.5
  {'min_version': '12.2.5.5', 'fixed_version': '12.2.5.5.210331', 'patch': '32709138', 'bundle': '32709138'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);
