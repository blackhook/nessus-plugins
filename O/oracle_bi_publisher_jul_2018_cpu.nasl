#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119940);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-2900", "CVE-2018-2925", "CVE-2018-2958");
  script_bugtraq_id(104767);

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (July 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher running on the
remote host is 11.1.1.7.x prior to 11.1.1.7.180717 or 11.1.1.9.x 
prior to 11.1.1.9.180717, similarly, versions  12.2.1.2.x prior to
12.2.1.2.180717 and 12.2.1.3.x prior to 12.2.1.3.180717 are affected 
as noted in the July 2018 Critical Patch Update advisory. 
The Oracle Business Intelligence Publisher installed on the remote
host is affected by multiple vulnerabilities:

  - A vulnerability exists on the Layout Tools, Oracle BI
    Publisher component of Oracle Fusion Middleware. An
    unauthenticated attacker can exploit the vulnerability
    via HTTP access to compromise BI Publisher. A
    successful attack could result in an unauthorized
    creation, deletion or modification of critical data on
    BI Publisher including read data to a subset of
    information (CVE-2018-2900).

  - A vulnerability exists on the Web Server, Oracle BI
    Publisher component of Oracle Fusion Middleware. A low
    privileged attacker with network access via HTTP can
    easily exploit the vulnerability to compromise Oracle
    BI Publisher. Unauthorized access to critical data
    hosted in the remote server can be possible after a
    successful exploit of the vulnerability
    (CVE-2018-2925).

  - A vulnerability exists on the BI Publisher Security,
    Oracle BI Publisher component of Oracle Fusion
    Middleware. An unauthenticated attacker with network
    access via HTTP can exploit the vulnerability to
    compromise Oracle BI Publisher. Unauthorized access to
    critical data hosted in the remote server can be
    possible after a successful exploit of the
    vulnerability (CVE-2018-2958).
  
Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0716163");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2958");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/28");

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

# 11.1.1.7.x - Bundle: 28119130 | Patch: 27916893
# 11.1.1.9.x - Bundle: 28119112 | Patch: 27982217
# 12.2.1.2.x - Bundle: 27916905 | Patch: 27916905
# 12.2.1.3.x - Bundle: 27329720 | Patch: 27329720
constraints = [
  {'min_version': '11.1.1.7', 'fixed_version': '11.1.1.7.180717', 'patch': '27916893', 'bundle': '28119130'},
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.180717', 'patch': '27982217', 'bundle': '28119112'},
  {'min_version': '12.2.1.2', 'fixed_version': '12.2.1.2.180717', 'patch': '27916905', 'bundle': '27916905'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.180717', 'patch': '27329720', 'bundle': '27329720'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);
