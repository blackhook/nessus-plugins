#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159902);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id(
    "CVE-2018-25032",
    "CVE-2022-21426",
    "CVE-2022-21434",
    "CVE-2022-21443",
    "CVE-2022-21449",
    "CVE-2022-21476",
    "CVE-2022-21496"
  );

  script_name(english:"Azul Zulu Java Multiple Vulnerabilities (2022-04-19)");

  script_set_attribute(attribute:"synopsis", value:
"Azul Zulu OpenJDK is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Azul Zulu installed on the remote host is prior to 6 < 6.47 / 7 < 7.53.0.16 / 8 < 8.61.0.18 / 11 <
11.55.18 / 13 < 13.47.16 / 15 < 15.39.16 / 17 < 17.33.16 / 18 < 18.30.12. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2022-04-19 advisory.

  - zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many
    distant matches. (CVE-2018-25032)

  - xml/jaxp (CVE-2022-21426)

  - core-libs/java.lang (CVE-2022-21434)

  - security-libs/java.security (CVE-2022-21443, CVE-2022-21449, CVE-2022-21476)

  - core-libs/javax.naming (CVE-2022-21496)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.azul.com/core/zulu-openjdk/release-notes/april-2022");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2022 Azul Zulu OpenJDK Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21496");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21476");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:azul:zulu");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zulu_java_nix_installed.nbin", "zulu_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Azul Zulu Java'];
var app_info = vcf::java::get_app_info(app:app_list);
var package_type = app_info['Reported Code'];

if ('NV' == package_type)
{
  audit(AUDIT_PACKAGE_NOT_AFFECTED, package_type);
}
else if ('SA' == package_type)
{
  var constraints = [
    { 'min_version' : '6.0.0', 'fixed_version' : '6.47', 'fixed_display' : 'Upgrade to a version 6.47 (SA) and above' },
    { 'min_version' : '7.0.0', 'fixed_version' : '7.53.0.16', 'fixed_display' : 'Upgrade to a version 7.53.0.16 (SA) and above' },
    { 'min_version' : '8.0.0', 'fixed_version' : '8.61.0.18', 'fixed_display' : 'Upgrade to a version 8.61.0.18 (SA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.55.18', 'fixed_display' : 'Upgrade to a version 11.55.18 (SA) and above' },
    { 'min_version' : '13.0.0', 'fixed_version' : '13.47.16', 'fixed_display' : 'Upgrade to a version 13.47.16 (SA) and above' },
    { 'min_version' : '15.0.0', 'fixed_version' : '15.39.16', 'fixed_display' : 'Upgrade to a version 15.39.16 (SA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.33.16', 'fixed_display' : 'Upgrade to a version 17.33.16 (SA) and above' },
    { 'min_version' : '18.0.0', 'fixed_version' : '18.30.12', 'fixed_display' : 'Upgrade to a version 18.30.12 (SA) and above' }
  ];
}
else if ('CA' == package_type)
{
  var constraints = [
    { 'min_version' : '7.0.0', 'fixed_version' : '7.54.0.13', 'fixed_display' : 'Upgrade to a version 7.54.0.13 (CA) and above' },
    { 'min_version' : '8.0.0', 'fixed_version' : '8.62.0.19', 'fixed_display' : 'Upgrade to a version 8.62.0.19 (CA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.56.19', 'fixed_display' : 'Upgrade to a version 11.56.19 (CA) and above' },
    { 'min_version' : '13.0.0', 'fixed_version' : '13.48.19', 'fixed_display' : 'Upgrade to a version 13.48.19 (CA) and above' },
    { 'min_version' : '15.0.0', 'fixed_version' : '15.40.19', 'fixed_display' : 'Upgrade to a version 15.40.19 (CA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.34.19', 'fixed_display' : 'Upgrade to a version 17.34.19 (CA) and above' },
    { 'min_version' : '18.0.0', 'fixed_version' : '18.30.11', 'fixed_display' : 'Upgrade to a version 18.30.11 (CA) and above' }
  ];
}
else
{
  audit(AUDIT_HOST_NOT, 'an affected package type');
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
