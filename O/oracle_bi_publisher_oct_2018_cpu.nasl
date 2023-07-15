#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120948);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-5645", "CVE-2018-3204", "CVE-2018-8013");
  script_bugtraq_id(97702, 104252, 105623);

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (October 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher running on the
remote host is 11.1.1.7.x prior to 11.1.1.7.181016, 11.1.1.9.x prior
to 11.1.1.9.181016, 12.2.1.3.x prior to 12.2.1.3.181016, or
12.2.1.4.x prior to 12.2.1.4.181016. It is, therefore, affected by 
multiple vulnerabilities as noted in the October 2018 Critical 
Patch Update advisory:

  - A deserialization vulnerability exists in Apache Log4j
    2.x before 2.8.2. An unauthenticated, remote attacker
    can exploit this, via a specially crafted binary, to
    execute arbitrary code on the target host
    (CVE-2017-5645).

  - An information disclosure vulnerability exists in 
    Analytics Server, Oracle BI Publisher.Supported version
    affected is 12.2.1.3.0 An unauthenticated, remote
    attacker can exploit this, via HTTP, to disclose 
    potentially sensitive information. Successful attacks
    require human interaction from a person other than the
    attacker and while the vulnerability is in Oracle
    Business Intelligence Enterprise Edition, attacks may 
    significantly impact additional products
    (CVE-2018-3204).

  - A deserialization vulnerability exists in Apache Batik 
    1.x before 1.10 due to subclass of `AbstractDocument`.
    An unauthenticated, remote attacker can exploit this, 
    via deserializing subclass of `AbstractDocument`, to
    execute arbitrary code on the target host
    (CVE-2018-8013).

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?705136d8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8013");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");

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

# 11.1.1.7.x - Bundle: 28632415 | Patch: 28500572
# 11.1.1.9.x - Bundle: 28632479 | Patch: 28609078
# 12.2.1.3.x - Bundle: 28291838 | Patch: 28291838
# 12.2.1.4.x - Bundle: 28500593 | Patch: 28500593
constraints = [
  {'min_version': '11.1.1.7', 'fixed_version': '11.1.1.7.181016', 'patch': '28500572', 'bundle': '28632415'},
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.181016', 'patch': '28609078', 'bundle': '28632479'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.181016', 'patch': '28291838', 'bundle': '28291838'},
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.181016', 'patch': '28500593', 'bundle': '28500593'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);
