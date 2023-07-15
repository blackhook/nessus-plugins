#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151209);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"OpenJDK 7 <= 7u281 / 8 <= 8u272 / 11.0.0 <= 11.0.9 / 13.0.0 <= 13.0.5 / 15.0.0 <= 15.0.1 Vulnerability (2021-01-19)");

  script_set_attribute(attribute:"synopsis", value:
"OpenJDK is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenJDK installed on the remote host is prior to 7 <= 7u281 / 8 <= 8u272 / 11.0.0 <= 11.0.9 / 13.0.0 <=
13.0.5 / 15.0.0 <= 15.0.1. It is, therefore, affected by a vulnerability as referenced in the 2021-01-19 advisory.

Please Note: Java CVEs do not always include OpenJDK versions, but are confirmed separately by Tenable using the patch
versions from the referenced OpenJDK security advisory.

  - One or more vulnerabilities was found in OpenJDK with no reported CVEs. (openjdk-2021-01-19)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://openjdk.java.net/groups/vulnerability/advisories/2021-01-19");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an OpenJDK version greater than 7u281 / 8u272 / 11.0.9 / 13.0.5 / 15.0.1");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:openjdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adoptopenjdk_nix_installed.nbin", "adoptopenjdk_win_installed.nbin", "openjdk_win_installed.nbin", "openjdk_nix_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = [
        'OpenJDK Java',
        'AdoptOpenJDK'
];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '7.0.0', 'max_version' : '7.0.281', 'fixed_display' : 'Upgrade to a version greater than 7u281' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.272', 'fixed_display' : 'Upgrade to a version greater than 8u272' },
  { 'min_version' : '11.0.0', 'max_version' : '11.0.9', 'fixed_display' : 'Upgrade to a version greater than 11.0.9' },
  { 'min_version' : '13.0.0', 'max_version' : '13.0.5', 'fixed_display' : 'Upgrade to a version greater than 13.0.5' },
  { 'min_version' : '15.0.0', 'max_version' : '15.0.1', 'fixed_display' : 'Upgrade to a version greater than 15.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
