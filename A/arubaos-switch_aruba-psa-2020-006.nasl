#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151188);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-11896",
    "CVE-2020-11897",
    "CVE-2020-11898",
    "CVE-2020-11899",
    "CVE-2020-11900",
    "CVE-2020-11901",
    "CVE-2020-11902",
    "CVE-2020-11903",
    "CVE-2020-11904",
    "CVE-2020-11905",
    "CVE-2020-11906",
    "CVE-2020-11907",
    "CVE-2020-11908",
    "CVE-2020-11909",
    "CVE-2020-11910",
    "CVE-2020-11911",
    "CVE-2020-11912",
    "CVE-2020-11913",
    "CVE-2020-11914"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0052");

  script_name(english:"ArubaOS-Switch Ripple20 Multiple Vulnerabilities (ARUBA-PSA-2020-006)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS-Switch installed on the remote host is affected by multiple vulnerabilities in the Treck
IP stack implementation. The vulnerabilities are collectively known as Ripple20, and can result in remote code
execution, denial of service (DoS), and information disclosure by remote, unauthenticated attackers.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2020-006.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the ArubaOS-Switch version mentioned in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:arubaos");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:arubanetworks:arubaos-switch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var constraints = [];

if (
    (model =~ "54[0-9][0-9]R" && 'zl2' >< model) ||
     model =~ "381[0-9]M"    ||
     model =~ "292[0-9]M"    ||
     model =~ "293[0-9][MF]" ||
     model =~ "292[0-9]"     ||
     model =~ "254[0-9]"     ||
     model =~ "2930F"        ||
     model =~ "253[0-9]Y[AB]"
   )
  constraints = [
    { 'min_version':'0.0', 'fixed_version':'16.08.0014' },
    { 'min_version':'16.09.0', 'fixed_version':'16.09.0012' },
    { 'min_version':'16.10.0', 'fixed_version':'16.10.0009' }
  ];
else if (model =~ "54[0-9]{2}" && 'zl' >< model)
  constraints = [{'fixed_version' : '16.02.0031' }];
else if (model =~ "38[0-9]{2}|262[0-9]")
  constraints = [{'fixed_version' : '16.04.0020' }];
else if (model =~ "2915")
  constraints = [{'fixed_version' : '15.16.0022' }];
else if (model =~ "2615")
  constraints = [{'fixed_version' : '15.16.0002' }];
else if (
    'HP' >< model && (
    (model =~ 'yl' && model =~ "62[0-9]{2}") ||
    (model =~ 'zl' && model =~ "82[0-9]{2}") ||
    model =~ "66[0-9]{2}")
  )
  constraints = [{'fixed_version' : '15.18.0023' }];
else if (
    'HP' >< model &&
    (model =~ "35[0-9]{2}")
  )
  constraints = [{'fixed_version' : '16.02.0031' }];
else if (!empty_or_null(model))
  audit(AUDIT_DEVICE_NOT_VULN, model);
else # Paranoid, no model case with widest possible range
  constraints = [
    { 'min_version':'0.0', 'fixed_version':'16.08.0014' },
    { 'min_version':'16.09.0', 'fixed_version':'16.09.0012' },
    { 'min_version':'16.10.0', 'fixed_version':'16.10.0009' }
  ];


vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
