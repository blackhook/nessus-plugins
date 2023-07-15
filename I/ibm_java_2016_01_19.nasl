#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160338);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id(
    "CVE-2015-7575",
    "CVE-2015-8126",
    "CVE-2015-8472",
    "CVE-2016-0402",
    "CVE-2016-0448",
    "CVE-2016-0466",
    "CVE-2016-0475",
    "CVE-2016-0483",
    "CVE-2016-0494"
  );
  script_xref(name:"IAVA", value:"2015-A-0312-S");
  script_xref(name:"IAVA", value:"2016-A-0023-S");
  script_xref(name:"IAVB", value:"2016-B-0041-S");

  script_name(english:"IBM Java 6.0 < 6.0.16.20 / 6.1 < 6.1.8.20 / 7.0 < 7.0.9.30 / 7.1 < 7.1.3.30 / 8.0 < 8.0.2.10 Multiple Vulnerabilities (Jan 19, 2016)");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 6.0 < 6.0.16.20 / 6.1 < 6.1.8.20 / 7.0 < 7.0.9.30 / 7.1
< 7.1.3.30 / 8.0 < 8.0.2.10. It is, therefore, affected by multiple vulnerabilities as referenced in the Oracle January
19 2016 CPU advisory.

  - Mozilla Network Security Services (NSS) before 3.20.2, as used in Mozilla Firefox before 43.0.2 and
    Firefox ESR 38.x before 38.5.2, does not reject MD5 signatures in Server Key Exchange messages in TLS 1.2
    Handshake Protocol traffic, which makes it easier for man-in-the-middle attackers to spoof servers by
    triggering a collision. (CVE-2015-7575)

  - Multiple buffer overflows in the (1) png_set_PLTE and (2) png_get_PLTE functions in libpng before 1.0.64,
    1.1.x and 1.2.x before 1.2.54, 1.3.x and 1.4.x before 1.4.17, 1.5.x before 1.5.24, and 1.6.x before 1.6.19
    allow remote attackers to cause a denial of service (application crash) or possibly have unspecified other
    impact via a small bit-depth value in an IHDR (aka image header) chunk in a PNG image. (CVE-2015-8126)

  - Buffer overflow in the png_set_PLTE function in libpng before 1.0.65, 1.1.x and 1.2.x before 1.2.55,
    1.3.x, 1.4.x before 1.4.18, 1.5.x before 1.5.25, and 1.6.x before 1.6.20 allows remote attackers to cause
    a denial of service (application crash) or possibly have unspecified other impact via a small bit-depth
    value in an IHDR (aka image header) chunk in a PNG image. NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2015-8126. (CVE-2015-8472)

  - Unspecified vulnerability in the Java SE and Java SE Embedded components in Oracle Java SE 6u105, 7u91,
    and 8u66 and Java SE Embedded 8u65 allows remote attackers to affect integrity via unknown vectors related
    to Networking. (CVE-2016-0402)

  - Unspecified vulnerability in the Java SE and Java SE Embedded components in Oracle Java SE 6u105, 7u91,
    and 8u66, and Java SE Embedded 8u65 allows remote authenticated users to affect confidentiality via
    vectors related to JMX. (CVE-2016-0448)

  - Unspecified vulnerability in the Java SE, Java SE Embedded, and JRockit components in Oracle Java SE
    6u105, 7u91, and 8u66; Java SE Embedded 8u65; and JRockit R28.3.8 allows remote attackers to affect
    availability via vectors related to JAXP. (CVE-2016-0466)

  - Unspecified vulnerability in the Java SE, Java SE Embedded, and JRockit components in Oracle Java SE 8u66;
    Java SE Embedded 8u65; and JRockit R28.3.8 allows remote attackers to affect confidentiality and integrity
    via unknown vectors related to Libraries. (CVE-2016-0475)

  - Unspecified vulnerability in Oracle Java SE 6u105, 7u91, and 8u66; Java SE Embedded 8u65; and JRockit
    R28.3.8 allows remote attackers to affect confidentiality, integrity, and availability via vectors related
    to AWT. NOTE: the previous information is from the January 2016 CPU. Oracle has not commented on third-
    party claims that this is a heap-based buffer overflow in the readImage function, which allows remote
    attackers to execute arbitrary code via crafted image data. (CVE-2016-0483)

  - Unspecified vulnerability in the Java SE and Java SE Embedded components in Oracle Java SE 6u105, 7u91,
    and 8u66 and Java SE Embedded 8u65 allows remote attackers to affect confidentiality, integrity, and
    availability via unknown vectors related to 2D. (CVE-2016-0494)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV80331");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV80579");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV80580");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV80581");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV80582");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV80583");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV80584");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV80585");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#Oracle_January_19_2016_CPU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32c5d6f8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle January 19 2016 CPU advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0494");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-8472");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
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
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.20' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.20' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.9.30' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.3.30' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.2.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
