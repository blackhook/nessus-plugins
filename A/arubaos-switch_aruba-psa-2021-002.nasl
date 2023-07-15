#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150788);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id("CVE-2021-25141");

  script_name(english:"ArubaOS-Switch DoS (ARUBA-PSA-2021-002)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"A security vulnerability has been identified in certain HPE and Aruba L2/L3 switch firmware. A data processing error
due to improper handling of an unexpected data type in user supplied information to the switch's management interface
has been identified. The data processing error could be exploited to cause a crash or reboot in the switch management
interface and/or possibly the switch itself leading to local denial of service (DoS). The user must have administrator
privileges to exploit this vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2021-002.txt");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25141");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:arubaos");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:arubanetworks:arubaos-switch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arubaos_installed.nbin", "arubaos_detect.nbin");
  script_require_ports("installed_sw/ArubaOS");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::aruba::combined_get_app_info(os_flavour:'ArubaOS-Switch');
var model = app_info['Model'];
if (empty_or_null(model) && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'ArubaOS-Switch', app_info.version);

var fixed_version  = '';

if (
    (model =~ "54[0-9][0-9]R" && 'zl2' >< model) ||
    '3810M' >< model ||
    model =~ "2930[MF]" ||
    model =~ "25[34]0"
   )
  fixed_version = '16.10.0012';
else if ('2920' >< model)
  fixed_version = '16.10.0011';
else if (
    (model =~ "54[0-9][0-9]" && 'zl' >< model) ||
    '3500' >< model
  )
  fixed_version = '16.02.0032';
else if (
    (model =~ "38[0-9][0-9]") ||
    '2620' >< model
  )
  fixed_version = '16.04.0022';
else if (
    'HP' >< model &&
    (model =~ 'yl' && model =~ "62[0-9][0-9]") ||
    (model =~ 'zl' && model =~ "82[0-9][0-9]")
  )
  fixed_version = '15.18.0024';
else if (
    'HP' >< model &&
    (model =~ "35[0-9][0-9]")
  )
  fixed_version = '16.02.0032';
else if (!empty_or_null(model))
  audit(AUDIT_DEVICE_NOT_VULN, model);
else # Paranoid case with no model = widest possible range
  fixed_version = '16.10.0012';

var constraints = [
  {'fixed_version' : fixed_version }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
