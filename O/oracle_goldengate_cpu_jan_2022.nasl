#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168057);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2018-1311", "CVE-2021-2351", "CVE-2021-23017");

  script_name(english:"Oracle GoldenGate Multiple Vulnerabilities (January 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A real-time data integration and replication application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle GoldenGate installed on the remote host is affected by the following vulnerabilities as noted in
the January 2022 CPU advisory :

  - Vulnerability in Oracle GoldenGate (component: Build Request (Apache Xerces-C++)). The supported version that is
    affected is Prior to 21.4.0.0.0. Difficult to exploit vulnerability allows unauthenticated attacker with network
    access via HTTP to compromise Oracle GoldenGate. Successful attacks of this vulnerability can result in takeover of
    Oracle GoldenGate. (CVE-2018-1311)

  - Vulnerability in Oracle GoldenGate (component: GG Market Place for Support (nginx)). The supported version that is
    affected is Prior to 21.4.0.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via UDP to compromise Oracle GoldenGate. Successful attacks of this vulnerability can result in unauthorized
    creation, deletion or modification access to critical data or all Oracle GoldenGate accessible data as well as
    unauthorized access to critical data or complete access to all Oracle GoldenGate accessible data and unauthorized
    ability to cause a partial denial of service (partial DOS) of Oracle GoldenGate. (CVE-2021-23017)

  - Vulnerability in Oracle GoldenGate (component: Database (OCCI)). Supported versions that are affected are Prior to
    21.5.0.0.220118, Prior to 19.1.0.0.220118 and Prior to 12.3.0.1. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via Oracle Net to compromise Oracle GoldenGate. Successful attacks
    require human interaction from a person other than the attacker and while the vulnerability is in Oracle GoldenGate,
    attacks may significantly impact additional products. Successful attacks of this vulnerability can result in
    takeover of Oracle GoldenGate. (CVE-2021-2351)");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html#AppendixGG");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23017");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2351");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:goldengate");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_goldengate_installed.nbin");
  script_require_keys("Oracle/GoldenGate/Installed");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_goldengate::get_app_info();

var constraints = [
  {
    'min_version'   : '19.1.0.0' ,
    'fixed_version' : '19.1.0.0.220118',
    'fixed_display' : '19.1.0.0.220118 (33742655 / 33742660 / 33742664 / 33742666)'
  },
  {
    'min_version'   : '21.3.0.0' ,
    'fixed_version' : '21.5.0.0.2',
    'fixed_display' : '21.5.0.0.2 (33833650 / 33833656)'
  }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
