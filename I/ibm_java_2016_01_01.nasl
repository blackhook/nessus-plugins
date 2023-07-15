#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160369);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id("CVE-2015-5041", "CVE-2015-7981", "CVE-2015-8540");

  script_name(english:"IBM Java 6.0 < 6.0.16.20 / 6.1 < 6.1.8.20 / 7.0 < 7.0.9.30 / 7.1 < 7.1.3.30 / 8.0 < 8.0.2.10 Multiple Vulnerabilities (Jan 1, 2016)");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 6.0 < 6.0.16.20 / 6.1 < 6.1.8.20 / 7.0 < 7.0.9.30 / 7.1
< 7.1.3.30 / 8.0 < 8.0.2.10. It is, therefore, affected by multiple vulnerabilities as referenced in the IBM Security
Update January 2016 advisory.

  - The J9 JVM in IBM SDK, Java Technology Edition 6 before SR16 FP20, 6 R1 before SR8 FP20, 7 before SR9
    FP30, and 7 R1 before SR3 FP30 allows remote attackers to obtain sensitive information or inject data by
    invoking non-public interface methods. (CVE-2015-5041)

  - The png_convert_to_rfc1123 function in png.c in libpng 1.0.x before 1.0.64, 1.2.x before 1.2.54, and 1.4.x
    before 1.4.17 allows remote attackers to obtain sensitive process memory information via crafted tIME
    chunk data in an image file, which triggers an out-of-bounds read. (CVE-2015-7981)

  - Integer underflow in the png_check_keyword function in pngwutil.c in libpng 0.90 through 0.99, 1.0.x
    before 1.0.66, 1.1.x and 1.2.x before 1.2.56, 1.3.x and 1.4.x before 1.4.19, and 1.5.x before 1.5.26
    allows remote attackers to have unspecified impact via a space character as a keyword in a PNG image,
    which triggers an out-of-bounds read. (CVE-2015-8540)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV72872");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV80611");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#IBM_Security_Update_January_2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3171242");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the IBM Security Update January 2016 advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8540");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-5041");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:java");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_java_nix_installed.nbin", "ibm_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['IBM Java'];
var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.20' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.20' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.9.30' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.3.30' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.2.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
