#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103936);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-5254",
    "CVE-2017-10034",
    "CVE-2017-10037",
    "CVE-2017-10060",
    "CVE-2017-10163"
  );
  script_bugtraq_id(
    101307,
    101310,
    101334,
    101357,
    101405
  );

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (October 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher running on the
remote host is 11.1.1.7.x prior to 11.1.1.7.171017 or 11.1.1.9.x
prior to 11.1.1.9.171017. It is, therefore, affected by multiple
vulnerabilities as noted in the October 2017 Critical Patch Update
advisory. Please consult the CVRF details for the applicable CVEs for
additional information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e07fa0e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2017 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5254");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin", "oracle_bi_publisher_detect.nasl");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
appname = 'Oracle Business Intelligence Publisher';
app_info = vcf::get_app_info(app:appname);

# 11.1.1.7.x - Bundle: 26906772 | Patch: 26831047
# 11.1.1.9.x - Bundle: 26909117 | Patch: 26918122
# 12.2.1.1.x - Bundle: 26642678 | Patch: 26642678
# 12.2.1.2.x - Bundle: 26642682 | Patch: 26642682

constraints = [
  {'min_version' : '11.1.1.7', 'fixed_version' : '11.1.1.7.171017', 'patch' : '26831047', 'bundle' : '26906772'},
  {'min_version' : '11.1.1.9', 'fixed_version' : '11.1.1.9.171017', 'patch' : '26918122', 'bundle' : '26909117'},
  {'min_version' : '12.2.1.1', 'fixed_version' : '12.2.1.1.171017', 'patch' : '26642678', 'bundle' : '26642678'},
  {'min_version' : '12.2.1.2', 'fixed_version' : '12.2.1.2.171017', 'patch' : '26642682', 'bundle' : '26642682'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);
