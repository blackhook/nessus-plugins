#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133268);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-5645");
  script_bugtraq_id(97702);

  script_name(english:"Oracle GoldenGate for Big Data 12.3.2.1.x < 12.3.2.1.2 Apache Log4j Insecure Deserialization RCE (Jan 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The Oracle GoldenGate for Big Data application on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle GoldenGate for Big Data application located on the remote
host 12.3.2.1.x less than 12.3.2.1.2. It is, therefore, affected by a remote code execution vulnerability due to
insecure deserialization of log events received by the Apache Log4j subcomponent's TCP or UDP socket server. An
unauthenticated, remote attacker can exploit this to execute arbitrary code by sending a specially crafted, serialized
binary payload.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14755ac7");
  # https://docs.oracle.com/en/middleware/goldengate/big-data/12.3.2.1/gbdrn/corrected-problems.html#GUID-4286C791-466E-42A2-92A6-2DF777A4A18E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7481d30");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle GoldenGate for Big Data version 12.3.2.1.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5645");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/28");

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

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'Oracle GoldenGate for Big Data';
app_info = vcf::get_app_info(app:app_name);

// January CPU says 12.3.2.1.1 is the affected version. There's conflicting information, but as this is a paranoid only
// check we'll flag for 12.3.2.1.x < 12.3.2.1.2.
constraints = [
  { 'min_version':'12.3.2.1', 'fixed_version':'12.3.2.1.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
