#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119939);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-7501", "CVE-2017-5662");
  script_bugtraq_id(78215, 97948);

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (April 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher running on the
remote host is 11.1.1.7.x prior to 11.1.1.7.180417 or 11.1.1.9.x 
prior to 11.1.1.9.180417, similarly, versions  12.2.1.2.x prior to
12.2.1.2.180116 and 12.2.1.3.x prior to 12.2.1.3.180116 are affected 
as noted in the April 2018 Critical Patch Update advisory. 
The Oracle Business Intelligence Publisher installed on the remote
host is affected by multiple vulnerabilities:

  - A vulnerability can be exploited by a remote attacker
    by sending a crafted serialized Java object. A
    successful attack would allow the attacker to execute
    arbitrary commands on the vulnerable server
    (CVE-2015-7501).

  - A vulnerability exists on Apache Batik before 1.9. 
    The vulnerability would allow an attacker to send a
    malicious SVG file to a user. An attacker who
    successfully exploits this vulnerability could result
    in the compromise of the server (CVE-2017-5662).

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76507bf8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7501");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
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

# 11.1.1.7.x - Bundle: 27617562 | Patch: 26831047
# 11.1.1.9.x - Bundle: 27737733 | Patch: 27570221

constraints = [
  {'min_version': '11.1.1.7', 'fixed_version': '11.1.1.7.180417', 'patch': '26831047', 'bundle': '27617562'},
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.180417', 'patch': '27570221', 'bundle': '27737733'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);
