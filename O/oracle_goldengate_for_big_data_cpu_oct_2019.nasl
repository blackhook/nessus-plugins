#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129973);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2018-15756");
  script_bugtraq_id(105703);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle GoldenGate for Big Data 12.3.1.1.x < 12.3.1.1.6 / 12.3.2.1.x < 12.3.2.1.5 Spring Framework DoS (Oct 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The Oracle GoldenGate for Big Data application on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle GoldenGate for Big Data application located on the remote
host is 12.3.1.1.x less than 12.3.1.1.6 or 12.3.2.1.x less than 12.3.2.1.5. It is, therefore, affected by a denial of
service (DoS) vulnerability. This vulnerability is due to its use of Spring Framework, which provides support for range
requests when serving static resources through the ResourceHttpRequestHandler or when an annotated controller returns
an org.springframework.core.io.Resource. An unauthenticated, remote attacker can exploit this issue by adding a range
header with a high number of ranges, or with wide ranges that overlap, or both to cause the application to stop
responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b370bc74");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the October 2019 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15756");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:goldengate_application_adapters:");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_goldengate_for_big_data_installed.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/Oracle GoldenGate for Big Data");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('vcf.inc');

// Paranoid because the detection is looking for the presence of JAR files. It's possible that the customer has JAR
// files from outdated versions on their system, but is not currently using them.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'Oracle GoldenGate for Big Data';
app_info = vcf::get_app_info(app:app_name);

constraints = [
  { 'min_version':'12.3.1.1', 'fixed_version':'12.3.1.1.6' },
  { 'min_version':'12.3.2.1', 'fixed_version':'12.3.2.1.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
