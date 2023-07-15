#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160343);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/29");

  script_cve_id("CVE-2021-41035");

  script_name(english:"IBM Java 7.0 < 7.0.11.0 / 7.1 < 7.1.5.0 / 8.0 < 8.0.7.0");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 7.0 < 7.0.11.0 / 7.1 < 7.1.5.0 / 8.0 < 8.0.7.0. It is,
therefore, affected by a vulnerability as referenced in the IBM Security Update November 2021 advisory.

  - In Eclipse Openj9 before version 0.29.0, the JVM does not throw IllegalAccessError for MethodHandles that
    invoke inaccessible interface methods. (CVE-2021-41035)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ35976");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#IBM_Security_Update_November_2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d03da2f4");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the IBM Security Update November 2021 advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41035");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/01");
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
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.11.0' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.5.0' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.7.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
