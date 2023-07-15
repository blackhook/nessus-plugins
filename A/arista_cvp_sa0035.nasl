#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138344);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

  script_cve_id("CVE-2018-12357");

  script_name(english:"Arista Networks CloudVision Portal Incorrect Permissions (SA0035)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks CloudVision Portal running on the remote device is affected by incorrect permissions.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks CloudVision Portal running on the remote device is affected by an incorrect permissions
vulnerability. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.  To retrieve patch level information this plugin requires the HTTP credentials of the web console.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/5432-security-advisory-35
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73e9e658");
  script_set_attribute(attribute:"solution", value:
"Apply the mitigation or upgrade to a fixed version as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12357");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:arista:cloudvision_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_cloudvision_portal_detect.nbin");
  script_require_keys("installed_sw/Arista CloudVision Portal", "Settings/ParanoidReport");

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:443);
app = 'Arista CloudVision Portal';

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

version_list = make_list(
  '2015.1.1',
  '2015.1.2',
  '2016.1.0',
  '2016.1.1',
  '2016.1.2',
  '2016.1.2.1',
  '2016.1.2.3',
  '2017.1.0',
  '2017.1.0.1',
  '2017.1.1',
  '2017.1.1.1',
  '2017.2.0',
  '2017.2.1',
  '2017.2.2',
  '2017.2.3',
  '2018.1.0',
  '2018.1.1'
);

vuln = FALSE;
foreach version (version_list)
{
  if (app_info['version'] == version)
  {
    vuln = TRUE;
    break;
  }
}

if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_info.app, build_url2(qs:app_info.path, port:app_info.port), app_info.version);

constraints = [
  { 'fixed_version':'2018.1.2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
