#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165257);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-27593");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/29");

  script_name(english:"QNAP Photo Station DeadBolt Ransomware (QSA-22-24)");

  script_set_attribute(attribute:"synopsis", value:
"A photo gallery application running on the remote NAS is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Photo Station running on the remote QNAP NAS is affected by a vulnerability. An externally controlled
reference to a resource vulnerability has been reported to affect QNAP NAS running Photo Station. If exploited, This
could allow an attacker to modify system files. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/qsa-22-24");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27593");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:qnap:photo_station");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:photo_station");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  constraints = [{'fixed_version' : '5.2.14'}];
else if (qts_version =~ "4\.3\.[0-3]([^0-9]|$)")
  constraints = [{'fixed_version' : '5.4.15'}];
else if ( (ver_compare(ver:qts_version, fix:'4.3.4') >= 0) &&
          (ver_compare(ver:qts_version, fix:'4.3.6') <=0))
  constraints = [{'fixed_version' : '5.7.18'}];
else if ((qts_version =~ "4\.5([^0-9]|$)") || (qts_version =~ "5\.0\.0([^0-9]|$)"))
  constraints = [{'fixed_version' : '6.0.22'}];
else if (qts_version =~ "5\.0\.1([^0-9]|$)")
  constraints = [{'fixed_version' : '6.1.2'}];
else
  audit(AUDIT_HOST_NOT, 'affected');

var app = vcf::combined_get_app_info(app:'QNAP Photo Station');

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE);
