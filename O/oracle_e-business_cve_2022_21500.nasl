#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(162672);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2022-21500");

  script_name(english:"Oracle E-Business Suite Security Alert Advisory (CVE-2022-21500");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business Suite installed on the remote host is missing a vendor provided security patch and
is therefore affected by an information disclosure vulnerability as described in the Oracle Security Alert Advisory
for CVE-2022-21500. An unauthenticated remote attacker can exploit the vulnerability to expose personally identifiable
information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/alert-cve-2022-21500.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the CVE-2022-21500 Oracle Security Alert Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21500");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}
include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_ebusiness::get_app_info();

var constraints = [
  { 'min_version' : '12.2.3', 'max_version' : '12.2.3.9999999', 'fix_patches' : '34201614, 34268647' },
  { 'min_version' : '12.2.4', 'max_version' : '12.2.8.9999999', 'fix_patches' : '34201614, 34268647, 34164667' },
  { 'min_version' : '12.2.9', 'max_version' : '12.2.9.9999999', 'fix_patches' : '34201614, 34268647, 34164667, 34197714' },
  { 'min_version' : '12.2.10', 'max_version' : '12.2.10.9999999', 'fix_patches' : '34201614, 34268647, 34164667, 34197573' },
  { 'min_version' : '12.2.11', 'max_version' : '12.2.11.9999999', 'fix_patches' : '34201614, 34268647, 34164667, 34197137' },
];

vcf::oracle_ebusiness::check_version_and_report(
  app_info    : app_info,
  severity    : SECURITY_WARNING,
  constraints : constraints,
  fix_date    : '202206'
);
