#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150081);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id("CVE-2019-5322");

  script_name(english:"ArubaOS-Switch 16.08 < 16.08.0009 / 16.09 < 16.09.0007 / 16.10 < 16.10.0003 (ARUBA-PSA-2020-001)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"A remotely exploitable information disclosure vulnerability is present in Aruba Intelligent Edge Switch models 5400,
3810, 2920, 2930, 2530 with GigT port, 2530 10/100 port, or 2540. The vulnerability impacts firmware 16.08.* before
16.08.0009, 16.09.* before 16.09.0007 and 16.10.* before 16.10.0003. The vulnerability allows an attacker to retrieve
sensitive system information. This attack can be carried out without user authentication under very specific conditions.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2020-001.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ArubaOS-Switch version 16.08.0009, 16.09.0007, 16.10.0003 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5322");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/01");

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

if (
  !empty_or_null(model) &&
  model !~ '54[0-9][0-9]R' &&
  '3810' >!< model &&
  '2920' >!< model &&
  '2930' >!< model &&
  '2530' >!< model &&
  '2540' >!< model
)
  audit(AUDIT_DEVICE_NOT_VULN, model);

# The vulnerability can only be exploited to retrieve system information under very specific conditions.
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'ArubaOS-Switch', app_info['version']);

var constraints = [
  {'min_version' : '16.08.0', 'fixed_version' : '16.08.0009' },
  {'min_version' : '16.09.0', 'fixed_version' : '16.09.0007' },
  {'min_version' : '16.10.0', 'fixed_version' : '16.10.0003' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
