#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126467);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2016-3092",
    "CVE-2017-10024",
    "CVE-2017-10025",
    "CVE-2017-10028",
    "CVE-2017-10029",
    "CVE-2017-10030",
    "CVE-2017-10035",
    "CVE-2017-10041",
    "CVE-2017-10043",
    "CVE-2017-10058",
    "CVE-2017-10059",
    "CVE-2017-10156",
    "CVE-2017-10157"
  );
  script_bugtraq_id(
    91453,
    99682,
    99694,
    99696,
    99697,
    99723,
    99724,
    99738,
    99740,
    99741,
    99742,
    99743,
    99820
  );

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (Jul 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher running on the
remote host is 11.1.1.7.x prior to 11.1.1.7.170718, 11.1.1.9.x prior to 11.1.1.9.170718, 
12.2.1.1.x prior to 12.2.1.1.170718, or 12.2.1.2.x prior to 12.2.1.2.170718. It is,
therefore, affected by  multiple vulnerabilities as noted in the
April 2019 Critical Patch Update advisory:

  - An unspecified vulnerability in the BI Publisher
    component of Oracle Fusion Middleware (subcomponent: BI Publisher Security)
    that could allow an unauthenticated attacker with network
    access via HTTP to compromise BI Publisher. A successful attack of
    this vulnerability could result in unauthorized access to critical data
    or complete access to all Oracle BI Publisher accessible data. (CVE-2017-10025)

  - An unspecified vulnerability in the BI Publisher
    component of Oracle Fusion Middleware (subcomponent: Layout Tools) that
    could allow an unauthenticated attacker with network access
    via HTTP to compromise BI Publisher. A successful attack of this vulnerability
    could result in unauthorized access to critical data
    or complete access to all Oracle BI Publisher accessible data.
    The attack requires human interaction. (CVE-2017-10024)

  - An unspecified vulnerability in the BI Publisher
    component of Oracle Fusion Middleware (subcomponent: Web Server) that
    could allow an unauthenticated attacker with network access
    via HTTP to compromise BI Publisher. A successful attack of this vulnerability
    could result in unauthorized access to critical data
    or complete access to all Oracle BI Publisher accessible data.
    The attack requires human interaction. (CVE-2017-10028)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d003111a");
  # https://support.oracle.com/rs?type=doc&id=2261562.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e68a1603");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2017 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10157");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-10156");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin", "oracle_bi_publisher_detect.nasl");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
appname = 'Oracle Business Intelligence Publisher';
app_info = vcf::get_app_info(app:appname);

# 11.1.1.7.x - Bundle: 26092384 | Patch: 26146768
# 11.1.1.9.x - Bundle: 26092391 | Patch: 26330183
# 12.2.1.1.x - Bundle: 26146804 | Patch: 26146804
# 12.2.1.2.x - Bundle: 26146793 | Patch: 26146793
constraints = [
  {'min_version': '11.1.1.7', 'fixed_version': '11.1.1.7.170718', 'patch': '26146768', 'bundle': '26092384'},
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.170718', 'patch': '26330183', 'bundle': '26092391'},
  {'min_version': '12.2.1.1', 'fixed_version': '12.2.1.1.170718', 'patch': '26146804', 'bundle': '26146804'},
  {'min_version': '12.2.1.2', 'fixed_version': '12.2.1.2.170718', 'patch': '26146793', 'bundle': '26146793'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);
