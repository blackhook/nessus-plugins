#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134225);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2016-0635", "CVE-2018-1258", "CVE-2018-1275");
  script_bugtraq_id(91869, 103771, 104222);

  script_name(english:"Oracle GoldenGate for Big Data 12.2.0.1.x < 12.2.0.1.10 / 12.3.1.1.x < 12.3.1.1.6 Multiple Vulnerabilities (Oct 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The Oracle GoldenGate for Big Data application on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle GoldenGate for Big Data application located on the remote host is 12.2.0.1.x less than
12.2.0.1.10 or 12.3.1.1.x less than 12.3.1.1.6. It is, therefore, affected by multiple vulnerabilities : 

  - An unspecified vulnerability exists in Oracle GoldenGate for Big Data.  An authenticated, remote attacker
    can exploit this, via unknown vectors, to compromise confidentiality, integrity, and availability.
    (CVE-2016-0635)

  - An authorization bypass vulnerability exists in Spring Framework 5.0.5 when used in conjunction with
    Spring Security and using method security. An authenticated, remote attacker can exploit this to gain
    unauthorized access to methods that should be restricted. (CVE-2018-1258)

  - A remote code execution vulnerability exists in the Spring Framework. An unauthenticated, remote attacker
    can exploit this to bypass authentication and execute arbitrary commands. (CVE-2018-1275)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2018.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the October 2018 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0635");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-1275");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:goldengate_application_adapters");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_goldengate_for_big_data_installed.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/Oracle GoldenGate for Big Data");

  exit(0);
}

include('vcf.inc');

// Paranoid because the detection is looking for the presence of JAR files. It's possible that the customer has JAR
// files from outdated versions on their system, but is not currently using them.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'Oracle GoldenGate for Big Data';
app_info = vcf::get_app_info(app:app_name);

constraints = [
  { 'min_version':'12.2.0.1', 'fixed_version':'12.2.0.1.10' },
  { 'min_version':'12.3.1.1', 'fixed_version':'12.3.1.1.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
