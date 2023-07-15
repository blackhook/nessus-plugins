#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160348);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2016-0686",
    "CVE-2016-0687",
    "CVE-2016-3422",
    "CVE-2016-3426",
    "CVE-2016-3427",
    "CVE-2016-3443",
    "CVE-2016-3449"
  );
  script_xref(name:"IAVA", value:"2016-A-0100-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"IBM Java 6.0 < 6.0.16.25 / 6.1 < 6.1.8.25 / 7.0 < 7.0.9.40 / 7.1 < 7.1.3.40 / 8.0 < 8.0.3.0 Multiple Vulnerabilities (Apr 19, 2016)");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 6.0 < 6.0.16.25 / 6.1 < 6.1.8.25 / 7.0 < 7.0.9.40 / 7.1
< 7.1.3.40 / 8.0 < 8.0.3.0. It is, therefore, affected by multiple vulnerabilities as referenced in the Oracle April 19
2016 CPU advisory.

  - Unspecified vulnerability in Oracle Java SE 6u113, 7u99, and 8u77 and Java SE Embedded 8u77 allows remote
    attackers to affect confidentiality, integrity, and availability via vectors related to Serialization.
    (CVE-2016-0686)

  - Unspecified vulnerability in Oracle Java SE 6u113, 7u99, and 8u77 and Java SE Embedded 8u77 allows remote
    attackers to affect confidentiality, integrity, and availability via vectors related to the Hotspot sub-
    component. (CVE-2016-0687)

  - Unspecified vulnerability in Oracle Java SE 6u113, 7u99, and 8u77 allows remote attackers to affect
    availability via vectors related to 2D. (CVE-2016-3422)

  - Unspecified vulnerability in Oracle Java SE 8u77 and Java SE Embedded 8u77 allows remote attackers to
    affect confidentiality via vectors related to JCE. (CVE-2016-3426)

  - Unspecified vulnerability in Oracle Java SE 6u113, 7u99, and 8u77; Java SE Embedded 8u77; and JRockit
    R28.3.9 allows remote attackers to affect confidentiality, integrity, and availability via vectors related
    to JMX. (CVE-2016-3427)

  - Unspecified vulnerability in Oracle Java SE 6u113, 7u99, and 8u77 allows remote attackers to affect
    confidentiality, integrity, and availability via vectors related to 2D. NOTE: the previous information is
    from the April 2016 CPU. Oracle has not commented on third-party claims that this issue allows remote
    attackers to obtain sensitive information via crafted font data, which triggers an out-of-bounds read.
    (CVE-2016-3443)

  - Unspecified vulnerability in Oracle Java SE 6u113, 7u99, and 8u77 allows remote attackers to affect
    confidentiality, integrity, and availability via vectors related to Deployment. (CVE-2016-3449)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV83999");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV84000");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV84026");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV84027");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV84028");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV84029");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV84030");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#Oracle_April_19_2016_CPU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd15ddc5");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle April 19 2016 CPU advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3443");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:java");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_java_nix_installed.nbin", "ibm_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['IBM Java'];
var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.25' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.25' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.9.40' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.3.40' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.3.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
