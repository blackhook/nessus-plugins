#TRUSTED 402943e7ca39608702a99cdba52a0d3a98e45360d5027b7fd329b316037f6fcb63d46a5dee908d0c0aefd39d42ac345a95f99f56f07556576e295637cdb593d8acebbcdbd39112a450d83af6d9b9e5a81505d16e2dee208ffcc97e0d5af920c0b8973929b215fb2c02977f08808cb9abd9b7fe39ef42ef706d2b742b582a1dcb45dee2a8ad15ad39c2ac31fa02c40ed6e1a8e1511ef22bf389295ec97ddd51dcd9a72207dc2e70c490828f6b4ee3196b418f3ccb814edfba4128129d2542b4c93900aaa05b7e167591665f4df7b3d34a3f9ca3d07aeb73a3c1bc837d4431b70078754f7b5595ff6c1f8ab307e9b8afd46ccd661a02f7da6cdf1d59cc594131c365eb598b0c531db946158e078247449f0faac06b0dccd73d416bbe90fb9f3860a14444ac1d8254e4c2744d8b3dbc8d89edb502a56d45e6c290378b2ed4e4236b66f35e37f5f1e78956783d6095da426699cc3e7ef855d0b138de92077c05282df60d0ab88cd1e3e7228b9b20464767fe00e74e9ee350be921c4b0735d01284ad4513732465c4d039a0032747dfd00a92ffdb2899f71fa65960f4de43bbe6895a23b036a394c86871e4c620e9682fde1d422208c0cf780a17ba23efd01f7c9311a2aa65b5e7c3cba4e26eb4963b312a6e9f0e56821358c3143a6900d9fbcc9ae43bbc55faaa8c3b7d3e58d6eb06c5391d2d4e026f5d9e327483316231ae510d0d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157877);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id("CVE-2021-1577");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw57556");
  script_xref(name:"CISCO-SA", value:"cisco-sa-capic-frw-Nt3RYxR2");

  script_name(english:"Cisco Application Policy Infrastructure Controller Arbitrary File Read and Write (cisco-sa-capic-frw-Nt3RYxR2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller is affected by a 
vulnerability in an API endpoint which could allow a remote, unauthenticated attacker to read or write 
arbitrary files on an affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-capic-frw-Nt3RYxR2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2af4b01f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw57556");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw57556");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1577");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}

include('ccf.inc');
include('http.inc');

var app_name = 'Cisco APIC Software';
var port = get_http_port(default:443);

var product_info = cisco::get_product_info(name:app_name, port:port);

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '3.2(10e)'},
  {'min_ver': '4.0', 'fix_ver': '4.2(6h)'},
  {'min_ver': '5.0', 'fix_ver': '5.1(3e)'}
];

var reporting = make_array(
  'port'     , port,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw57556',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
