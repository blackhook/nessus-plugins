#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153926);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-2161", "CVE-2021-2163");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Azul Zulu Java OpenJDK Vulnerability (2021-04-20)");

  script_set_attribute(attribute:"synopsis", value:
"Azul Zulu Java is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Azul Zulu installed on the remote host is prior to 6 <= 6.39.0.14 (SA) / 7 <= 7.45.0.12 (SA) or 
7.46.0.11 (CA) / 8 <= 8.53.0.12 (SA) or 8.54.0.21 (CA) / 11.0.0 <= 11.47.18 (SA) or 11.48.21 (CA) / 13.0.0 <= 
13.39.14 (SA) or 13.40.15 (CA) / 15.0.0 <= 15.31.14 (SA) or 15.32.15 (CA) / 16.0.0 <= 16.30.20 (SA) or 16.30.19 (CA). 
It is, therefore, affected by a vulnerability as referenced in the 2021-04-20 advisory. 
  - A vulnerability in Java SE, SE Embedded and Oracle GraalVM Enterprise Edition allows unauthenticated remote attacker
    to compromise the system which can result in an unauthorized creation, deletion or modification access to critical
    data. (CVE-2021-2161)
Note: 
  - Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.azul.com/core/zulu-openjdk/release-notes/april-2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Azul Zulu OpenJDK Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2161");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:azul:zulu");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { 'min_version' : '6.0.0', 'fixed_version' : '6.39.0.14', 'fixed_display' : 'Upgrade to a version 6.39.0.14 (SA) and above' },
    { 'min_version' : '7.0.0', 'fixed_version' : '7.45.0.12', 'fixed_display' : 'Upgrade to a version 7.45.0.12 (SA) and above' },
    { 'min_version' : '8.0.0', 'fixed_version' : '8.53.0.12', 'fixed_display' : 'Upgrade to a version 8.53.0.12 (SA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.47.18', 'fixed_display' : 'Upgrade to a version 11.47.18 (SA) and above' },
    { 'min_version' : '13.0.0', 'fixed_version' : '13.39.14', 'fixed_display' : 'Upgrade to a version 13.39.14 (SA) and above' },
    { 'min_version' : '15.0.0', 'fixed_version' : '15.31.14', 'fixed_display' : 'Upgrade to a version 15.31.14 (SA) and above' },
    { 'min_version' : '16.0.0', 'fixed_version' : '16.30.20', 'fixed_display' : 'Upgrade to a version 16.30.20 (SA) and above' }
  ];
}
else if ('CA' == package_type)
{
  var constraints = [
    { 'min_version' : '7.0.0', 'fixed_version' : '7.46.0.11', 'fixed_display' : 'Upgrade to a version 7.46.0.11 (CA) and above' },
    { 'min_version' : '8.0.0', 'fixed_version' : '8.54.0.21', 'fixed_display' : 'Upgrade to a version 8.54.0.21 (CA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.48.21', 'fixed_display' : 'Upgrade to a version 11.48.21 (CA) and above' },
    { 'min_version' : '13.0.0', 'fixed_version' : '13.40.15', 'fixed_display' : 'Upgrade to a version 13.40.15 (CA) and above' },
    { 'min_version' : '14.0.0', 'fixed_version' : '14.29.24', 'fixed_display' : 'Upgrade to a version 14.29.24 (CA) and above' },
    { 'min_version' : '15.0.0', 'fixed_version' : '15.32.15', 'fixed_display' : 'Upgrade to a version 15.32.15 (CA) and above' },
    { 'min_version' : '16.0.0', 'fixed_version' : '16.30.19', 'fixed_display' : 'Upgrade to a version 16.30.19 (CA) and above' }
  ];
}
else
{
  audit(AUDIT_HOST_NOT, 'an affected package type');
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);