#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151905);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-2341",
    "CVE-2021-2369",
    "CVE-2021-2388",
    "CVE-2021-2432"
  );

  script_name(english:"OpenJDK 7 <= 7u301 / 8 <= 8u292 / 11.0.0 <= 11.0.11 / 13.0.0 <= 13.0.7 / 15.0.0 <= 15.0.3 / 16.0.0 <= 16.0.1 Multiple Vulnerabilities (2021-07-20)");

  script_set_attribute(attribute:"synopsis", value:
"OpenJDK is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenJDK installed on the remote host is prior to 7 <= 7u301 / 8 <= 8u292 / 11.0.0 <= 11.0.11 / 13.0.0 <=
13.0.7 / 15.0.0 <= 15.0.3 / 16.0.0 <= 16.0.1. It is, therefore, affected by multiple vulnerabilities as referenced in
the 2021-07-20 advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's
self-reported version number.

Please Note: Java CVEs do not always include OpenJDK versions, but are confirmed separately by Tenable using the patch
versions from the referenced OpenJDK security advisory.");
  script_set_attribute(attribute:"see_also", value:"https://openjdk.java.net/groups/vulnerability/advisories/2021-07-20");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an OpenJDK version greater than 7u301 / 8u292 / 11.0.11 / 13.0.7 / 15.0.3 / 16.0.1");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

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
  { 'min_version' : '7.0.0', 'max_version' : '7.0.301', 'fixed_display' : 'Upgrade to a version greater than 7u301' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.292', 'fixed_display' : 'Upgrade to a version greater than 8u292' },
  { 'min_version' : '11.0.0', 'max_version' : '11.0.11', 'fixed_display' : 'Upgrade to a version greater than 11.0.11' },
  { 'min_version' : '13.0.0', 'max_version' : '13.0.7', 'fixed_display' : 'Upgrade to a version greater than 13.0.7' },
  { 'min_version' : '15.0.0', 'max_version' : '15.0.3', 'fixed_display' : 'Upgrade to a version greater than 15.0.3' },
  { 'min_version' : '16.0.0', 'max_version' : '16.0.1', 'fixed_display' : 'Upgrade to a version greater than 16.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
