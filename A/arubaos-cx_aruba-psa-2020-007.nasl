#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150987);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id("CVE-2019-5320", "CVE-2019-5321");

  script_name(english:"ArubaOS-Switch Multiple Vulnerabilities (ARUBA-PSA-2020-007)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS-Switch installed on the remote host is 16.08.* prior to version 16.08.0009, 16.09.* prior to
16.09.0007 or 16.10.* prior to 16.10.0003. It is, therefore, affected by multiple vulnerabilities, as follows:

  - A vulnerability in the Web Management Interface allows an attacker to gain access to the administration of
    the switch. This attack can only occur if a switch administrator is already logged into the switch Web
    Management Interface, and is convinced by an attacker to click on the specially crafted URL. (CVE-2019-5321)

  - A vulnerability in the Web Management Interface allows an attacker to inject JavaScript code by sending a
    crafted URL to the administrator user of the switch. This attack can only occur if a switch administrator is
    already logged into the switch Web Management Interface, and is convinced by an attacker to click on the
    specially crafted URL. (CVE-2019-5320)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2020-007.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ArubaOS-Switch version 16.08.0014, 16.09.0012, 16.10.0009 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5321");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:arubaos");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:arubanetworks:arubaos-switch");
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


var constraints = [
  {'min_version':'16.08.0', 'max_version' : '16.08.0009', 'fixed_version' : '16.08.0014' },
  {'min_version':'16.09.0', 'max_version' : '16.09.0007', 'fixed_version' : '16.09.0012' },
  {'min_version':'16.10.0', 'max_version' : '16.10.0003', 'fixed_version' : '16.10.0009' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
