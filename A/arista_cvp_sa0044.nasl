#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138218);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/09");

  script_cve_id("CVE-2019-18181");

  script_name(english:"Arista Networks CloudVision Portal Privilege Escalation (SA0044)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks CloudVision Portal running on the remote device is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks CloudVision Portal running on the remote device is affected by a privilege escalation
vulnerability. Users with read-only permissions can exploit this to bypass permissions for restricted functionality via
CVP API calls through the Configlet Builder modules. This vulnerability can potentially enable authenticated users with
read-only access to take actions that are otherwise restricted in the GUI.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.  To retrieve version information this plugin requires the HTTP credentials of the web console.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/9001-security-advisory-44
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f4300b8");
  script_set_attribute(attribute:"solution", value:
"Apply the mitigation or upgrade to a fixed version as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18181");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:arista:cloudvision_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_cloudvision_portal_detect.nbin");
  script_require_keys("installed_sw/Arista CloudVision Portal");

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:443);
app = 'Arista CloudVision Portal';

get_install_count(app_name:app, exit_if_zero:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

# 2018.2 release train has a hotfix we don't check for, so require paranoia in this case only
if (app_info['version'] =~ "^2018.2" && (report_paranoia < 2))
  audit(AUDIT_PARANOID);

constraints = [
  { 'min_version':'2018.1', 'fixed_version':'2018.3', 'fixed_display':'2019.1.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
