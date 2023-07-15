#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(172281);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2023-20032", "CVE-2023-20052");

  script_name(english:"ClamAV < 0.103.8 / 0.104.x < 0.105.2 / 1.0.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus service running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the ClamAV clamd antivirus daemon running on the remote host is prior to 0.103.8, 0.104.x
prior to 0.105.2, or 1.0.0. It is, therefore, affected by multiple vulnerabilities:

  - A vulnerability in the HFS+ partition file parser of ClamAV versions 1.0.0 and earlier, 0.105.1 and earlier, and
    0.103.7 and earlier could allow an unauthenticated, remote attacker to execute arbitrary code. (CVE-2023-20032)

  - A vulnerability in the DMG file parser of ClamAV versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and
    earlier could allow an unauthenticated, remote attacker to access sensitive information on an affected device.
    (CVE-2023-20052)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://blog.clamav.net/2023/02/clamav-01038-01052-and-101-patch.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ClamAV version 0.103.8, 0.105.2, or 1.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20032");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("installed_sw/ClamAV");

  exit(0);
}

include('vcf.inc');

var app = 'ClamAV';
get_install_count(app_name:app, exit_if_zero:TRUE);
var port = get_service(svc:'clamd', default:3310, exit_on_fail:TRUE);
var app_info = vcf::get_app_info(app:app, port:port, kb_ver:'Antivirus/ClamAV/version');

var constraints = [
  {'fixed_version':'0.103.8'},
  {'min_version':'0.104.0', 'fixed_version':'0.105.2'},
  {'min_version':'1.0.0', 'fixed_version':'1.0.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
