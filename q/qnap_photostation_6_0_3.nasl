##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162137);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/12");

  script_cve_id(
    "CVE-2019-7192",
    "CVE-2019-7193",
    "CVE-2019-7194",
    "CVE-2019-7195"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"QNAP Photo Station Multiple Vulnerabilities (NAS-201911-25)");

  script_set_attribute(attribute:"synopsis", value:
"A photo gallery application running on the remote NAS is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Photo Station running on the remote QNAP NAS is affected by multiple vulnerabilities,
as follows:

  - This improper input validation vulnerability allows remote attackers to inject arbitrary code to the
    system. To fix the vulnerability, QNAP recommend updating QTS to their latest versions. (CVE-2019-7193)

  - This improper access control vulnerability allows remote attackers to gain unauthorized access to the
    system. To fix these vulnerabilities, QNAP recommend updating Photo Station to their latest versions.
    (CVE-2019-7192)

  - This external control of file name or path vulnerability allows remote attackers to access or modify
    system files. To fix the vulnerability, QNAP recommend updating Photo Station to their latest versions.
    (CVE-2019-7194, CVE-2019-7195)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/zh-tw/security-advisory/nas-201911-25");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7193");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-7195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:qnap:photo_station");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:photo_station");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_photostation_detect.nbin", "qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin");
  script_require_ports("Services/www", 8080, "installed_sw/QNAP QTS", "installed_sw/QNAP Photo Station");

  exit(0);
}

include('vcf.inc');
include('install_func.inc');

var qts_installs = get_combined_installs(app_name:'QNAP QTS');

if (qts_installs[0] != IF_OK || max_index(qts_installs[1]) < 1)
  audit(AUDIT_HOST_NOT, 'affected');

# Only 1 install of QTS is possible per target
var qts_install = qts_installs[1][0];
var qts_version = qts_install.version;

# Photo Station fixed ver depends on QTS version
var constraints;
if (qts_version =~ "4\.2\.6([^0-9]|$)")
  constraints = [{'fixed_version' : '5.2.11'}];
else if (qts_version =~ "4\.3\.[0-3]([^0-9]|$)")
  constraints = [{'fixed_version' : '5.4.9'}];
else if ( (ver_compare(ver:qts_version, fix:'4.3.4') >= 0) &&
          (ver_compare(ver:qts_version, fix:'4.4.0') <=0))
  constraints = [{'fixed_version' : '5.7.10'}];
else if (qts_version =~ "4\.4\.1([^0-9]|$)")
  constraints = [{'fixed_version' : '6.0.3'}];
else
  audit(AUDIT_HOST_NOT, 'affected');

var app = vcf::combined_get_app_info(app:'QNAP Photo Station');

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE);
