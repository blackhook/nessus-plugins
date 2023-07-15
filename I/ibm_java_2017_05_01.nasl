#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160346);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/29");

  script_cve_id(
    "CVE-2016-9840",
    "CVE-2016-9841",
    "CVE-2016-9842",
    "CVE-2016-9843",
    "CVE-2017-1289"
  );
  script_xref(name:"IAVA", value:"2017-A-0306-S");
  script_xref(name:"IAVA", value:"2020-A-0328");
  script_xref(name:"IAVA", value:"2018-A-0226-S");

  script_name(english:"IBM Java 6.0 < 6.0.16.45 / 6.1 < 6.1.8.45 / 7.0 < 7.0.10.5 / 7.1 < 7.1.4.5 / 8.0 < 8.0.4.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 6.0 < 6.0.16.45 / 6.1 < 6.1.8.45 / 7.0 < 7.0.10.5 / 7.1
< 7.1.4.5 / 8.0 < 8.0.4.5. It is, therefore, affected by multiple vulnerabilities as referenced in the IBM Security
Update May 2017 advisory.

  - inftrees.c in zlib 1.2.8 might allow context-dependent attackers to have unspecified impact by leveraging
    improper pointer arithmetic. (CVE-2016-9840)

  - inffast.c in zlib 1.2.8 might allow context-dependent attackers to have unspecified impact by leveraging
    improper pointer arithmetic. (CVE-2016-9841)

  - The inflateMark function in inflate.c in zlib 1.2.8 might allow context-dependent attackers to have
    unspecified impact via vectors involving left shifts of negative integers. (CVE-2016-9842)

  - The crc32_big function in crc32.c in zlib 1.2.8 might allow context-dependent attackers to have
    unspecified impact via vectors involving big-endian CRC calculation. (CVE-2016-9843)

  - IBM SDK, Java Technology Edition is vulnerable XML External Entity Injection (XXE) error when processing
    XML data. A remote attacker could exploit this vulnerability to expose highly sensitive information or
    consume memory resources. IBM X-Force ID: 125150. (CVE-2017-1289)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV95268");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV95456");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#IBM_Security_Update_May_2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5a419df");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the IBM Security Update May 2017 advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9843");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/01");
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
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.45' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.45' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10.5' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.4.5' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.4.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
