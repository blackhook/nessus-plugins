#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160339);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/29");

  script_cve_id(
    "CVE-2019-4473",
    "CVE-2019-11771",
    "CVE-2019-11772",
    "CVE-2019-11775"
  );

  script_name(english:"IBM Java 7.0 < 7.0.10.50 / 7.1 < 7.1.4.50 / 8.0 < 8.0.5.40 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 7.0 < 7.0.10.50 / 7.1 < 7.1.4.50 / 8.0 < 8.0.5.40. It
is, therefore, affected by multiple vulnerabilities as referenced in the IBM Security Update July 2019 advisory.

  - Multiple binaries in IBM SDK, Java Technology Edition 7, 7R, and 8 on the AIX platform use insecure
    absolute RPATHs, which may facilitate code injection and privilege elevation by local users. IBM X-Force
    ID: 163984. (CVE-2019-4473)

  - AIX builds of Eclipse OpenJ9 before 0.15.0 contain unused RPATHs which may facilitate code injection and
    privilege elevation by local users. (CVE-2019-11771)

  - In Eclipse OpenJ9 prior to 0.15, the String.getBytes(int, int, byte[], int) method does not verify that
    the provided byte array is non-null nor that the provided index is in bounds when compiled by the JIT.
    This allows arbitrary writes to any 32-bit address or beyond the end of a byte array within Java code run
    under a SecurityManager. (CVE-2019-11772)

  - All builds of Eclipse OpenJ9 prior to 0.15 contain a bug where the loop versioner may fail to privatize a
    value that is pulled out of the loop by versioning - for example if there is a condition that is moved out
    of the loop that reads a field we may not privatize the value of that field in the modified copy of the
    loop allowing the test to see one value of the field and subsequently the loop to see a modified field
    value without retesting the condition moved out of the loop. This can lead to a variety of different
    issues but read out of array bounds is one major consequence of these problems. (CVE-2019-11775)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ17982");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ17983");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ17984");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ18003");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#IBM_Security_Update_July_2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ffdf7da");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the IBM Security Update July 2019 advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11772");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/01");
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
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10.50' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.4.50' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.5.40' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
