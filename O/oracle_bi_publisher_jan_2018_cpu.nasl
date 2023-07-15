#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119885);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-2179", "CVE-2017-10068", "CVE-2018-2715");
  script_bugtraq_id(92987, 102535, 102558);

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (January 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher running on the
remote host is 11.1.1.9.x prior to 11.1.1.9.180116 or
12.2.1.2.x prior to 12.2.1.2.180116 or 12.2.1.3.x prior to 
12.2.1.3.180116. 
It is, therefore, affected by multiple vulnerabilities as noted in 
the January 2018 Critical Patch Update advisory.
The Oracle Business Intelligence Publisher installed on the remote
host is affected by multiple vulnerabilities:

  - An improper restriction of the lifetime of queues entries
    associated with unused our-of-order messages allows an
    remote attacker to cause a denial of service in the 
    DTLS implementationof OpenSSL before 1.1.0
    (CVE-2016-2179).
  - An easily exploitable vulnerability allows an
    unauthenticated attacker with network access to 
    compromise Oracle Business Intelligence Enterprise
    Edition via HTTP. A Successful attack of this 
    vulnerability would result in unauthorized access to
    data as well as unauthorized update, insert or delete.
    This attack would required human interaction. 
    (CVE-2017-10068).
  - An low privileged attacker with network access via HTTP
    can exploit a vulnerability in Oracle Business
    Intelligence Enterprise Edition. A successful attack
    would allow the unauthorized access to critical data
    (CVE-2018-2715).

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ee54bd8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin", "oracle_bi_publisher_detect.nasl");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
appname = 'Oracle Business Intelligence Publisher';
app_info = vcf::get_app_info(app:appname);

# 11.1.1.9.x - Bundle: 27281232 | Patch: 27321329
# 12.2.1.2.x - Bundle: 27072632 | Patch: 27072632
# 12.2.1.3.x - Bundle: 26796833 | Patch: 26796833

constraints = [
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.180116', 'patch': '27321329', 'bundle': '27281232'},
  {'min_version': '12.2.1.2', 'fixed_version': '12.2.1.2.180116', 'patch': '27072632', 'bundle': '28500593'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.180116', 'patch': '26796833', 'bundle': '26796833'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);
