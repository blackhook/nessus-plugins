#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150076);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id("CVE-2020-7122");

  script_name(english:"ArubaOS-CX < 10.04.2000 Memory Corruption (ARUBA-PSA-2020-009)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS-CX installed on the remote host is prior to version 10.04.2000. Two memory corruption
vulnerabilities in the Aruba CX Switches Series 6200F, 6300, 6400, 8320, 8325, and 8400 have been found. Successful
exploitation of these vulnerabilities could result in Local Denial of Service of the LLDP (Link Layer Discovery
Protocol) process in the switch.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2020-009.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ArubaOS-CX version 10.04.2000 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7122");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:arubaos");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:arubanetworks:arubaos-cx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arubaos_installed.nbin", "arubaos_detect.nbin");
  script_require_keys("installed_sw/ArubaOS");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::aruba::combined_get_app_info(os_flavour:'ArubaOS-CX');

var model = app_info['Model'];

# No model available for CX remotely
if (empty_or_null(model) && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'ArubaOS-CX', app_info.version);

if (
  !empty_or_null(model) &&
  '8400' >!< model &&
  '8325' >!< model &&
  '8320' >!< model &&
  '6400' >!< model &&
  '6300' >!< model &&
  '6200' >!< model
)
  audit(AUDIT_DEVICE_NOT_VULN, model);

var constraints = [
  {'max_version' : '10.04.1000', 'fixed_display' : '10.04.2000 and above' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
