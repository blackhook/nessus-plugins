#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160358);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/29");

  script_cve_id(
    "CVE-2016-3485",
    "CVE-2016-3511",
    "CVE-2016-3550",
    "CVE-2016-3587",
    "CVE-2016-3598",
    "CVE-2016-3606",
    "CVE-2016-3610"
  );
  script_xref(name:"IAVA", value:"2016-A-0186-S");

  script_name(english:"IBM Java 6.0 < 6.0.16.30 / 6.1 < 6.1.8.30 / 7.0 < 7.0.9.50 / 7.1 < 7.1.3.50 / 8.0 < 8.0.3.10 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 6.0 < 6.0.16.30 / 6.1 < 6.1.8.30 / 7.0 < 7.0.9.50 / 7.1
< 7.1.3.50 / 8.0 < 8.0.3.10. It is, therefore, affected by multiple vulnerabilities as referenced in the Oracle July 19
2016 CPU advisory.

  - Unspecified vulnerability in Oracle Java SE 6u115, 7u101, and 8u92; Java SE Embedded 8u91; and JRockit
    R28.3.10 allows local users to affect integrity via vectors related to Networking. (CVE-2016-3485)

  - Unspecified vulnerability in Oracle Java SE 7u101 and 8u92 allows local users to affect confidentiality,
    integrity, and availability via vectors related to Deployment. (CVE-2016-3511)

  - Unspecified vulnerability in Oracle Java SE 6u115, 7u101, and 8u92 and Java SE Embedded 8u91 allows remote
    attackers to affect confidentiality via vectors related to Hotspot. (CVE-2016-3550)

  - Unspecified vulnerability in Oracle Java SE 8u92 and Java SE Embedded 8u91 allows remote attackers to
    affect confidentiality, integrity, and availability via vectors related to Hotspot. (CVE-2016-3587)

  - Unspecified vulnerability in Oracle Java SE 8u92 and Java SE Embedded 8u91 allows remote attackers to
    affect confidentiality, integrity, and availability via vectors related to Libraries, a different
    vulnerability than CVE-2016-3610. (CVE-2016-3598)

  - Unspecified vulnerability in Oracle Java SE 7u101 and 8u92 and Java SE Embedded 8u91 allows remote
    attackers to affect confidentiality, integrity, and availability via vectors related to Hotspot.
    (CVE-2016-3606)

  - Unspecified vulnerability in Oracle Java SE 8u92 and Java SE Embedded 8u91 allows remote attackers to
    affect confidentiality, integrity, and availability via vectors related to Libraries, a different
    vulnerability than CVE-2016-3598. (CVE-2016-3610)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV87081");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV87082");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV87083");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#Oracle_July_19_2016_CPU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?609b25c4");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle July 19 2016 CPU advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3610");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:java");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.30' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.30' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.9.50' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.3.50' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.3.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
