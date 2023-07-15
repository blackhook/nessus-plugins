#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142210);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-2904",
    "CVE-2019-11358",
    "CVE-2020-1945",
    "CVE-2020-1951",
    "CVE-2020-9484"
  );
  script_bugtraq_id(108023);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Business Process Management Suite (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Process Management Suite installed on the remote host is affected by the following
vulnerabilities as referenced in the October 2020 CPU advisory:  

  - Vulnerability in the Runtime Engine (Application Development Framework). An unauthenticated, remote
    attacker with network access via HTTP can exploit this issue to compromise the Oracle Business Process
    Management Suite. Successful attacks require human interaction from a person other than the attacker and
    while the vulnerability is in Oracle Business Process Management Suite, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or
    delete access to some of Oracle Business Process Management Suite accessible data as well as unauthorized
    read access to a subset of Oracle Business Process Management Suite accessible data. (CVE-2019-2904)

  - Vulnerability in the Runtime Engine (Apache Ant). An authenticated, local attacker can exploit this issue
    to compromise the Oracle Business Process Management Suite. Successful attacks of this vulnerability can
    result in unauthorized creation, deletion or modification access to critical data or all Oracle Business
    Process Management Suite accessible data as well as unauthorized access to critical data or complete
    access to all Oracle Business Process Management Suite accessible data. (CVE-2020-1945)

  - Vulnerability in the Runtime Engine (jQuery). An unauthenticated, remote attacker with network access via
    HTTP can exploit this issue to compromise Oracle Business Process Management Suite. Successful attacks
    require human interaction from a person other than the attacker and while the vulnerability is in Oracle
    Business Process Management Suite, attacks may significantly impact additional products. Successful
    attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle
    Business Process Management Suite accessible data as well as unauthorized read access to a subset of
    Oracle Business Process Management Suite accessible data. (CVE-2019-11358)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2904");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_process_management_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bpm_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Process Manager");

  exit(0);
}

include('vcf.inc');

app = 'Oracle Business Process Manager';
app_info = vcf::get_app_info(app:app);

constraints = [
  { 'min_version':'12.2.1.3.0', 'fixed_version' : '12.2.1.3.200901' },
  { 'min_version':'12.2.1.4.0', 'fixed_version' : '12.2.1.4.200917' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
