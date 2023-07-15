#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86545);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-4838", "CVE-2015-4909");
  script_bugtraq_id(77167, 77174);

  script_name(english:"Oracle JDeveloper Multiple Vulnerabilities (October 2015 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A software development application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is
missing a security patch. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the ADF Faces subcomponent
    that allows an authenticated, remote attacker to
    disclose sensitive information. (CVE-2015-4838)

  - An unspecified flaw exists in the ADF Faces subcomponent
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2015-4909)");
  # https://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?404a1fb9");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4909");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdeveloper");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_jdeveloper_installed.nbin");
  script_require_keys("installed_sw/Oracle JDeveloper");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_jdev::get_app_info();

var constraints = [
  { 'min_version':'11.1.2.4', 'fixed_version':'11.1.2.4.151020', 'missing_patch':'21773974' },
  { 'min_version':'12.1.2.0', 'fixed_version':'12.1.2.0.151020', 'missing_patch':'21773977' },
  { 'min_version':'12.1.3.0', 'fixed_version':'12.1.3.0.151020', 'missing_patch':'21773981' }
];

vcf::oracle_jdev::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_WARNING,
  constraints:constraints
);
