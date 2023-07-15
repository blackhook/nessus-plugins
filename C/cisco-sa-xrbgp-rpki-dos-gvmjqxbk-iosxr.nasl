#TRUSTED 1f1df7434041772b83e6e58c4a2d329eb8fdaf01de8060a018bdb6884641b1807256dc18a76da5c7a3a4eabfbfff308f8b755d0698aaddc66df8e49e8d4e3c5374698ac62119c17c74680cdfcd1fb8ce641b758374f6e96ead03661a8d99eb62f4a961db1bb62dc718d63494ee265c8e840aae899e3e80a0ffd835c417ecd391bb9ec8b0ad2486cf5de7eb8add4960902bd42e55caf8459c01cff0b8df5edf1ccb152367d26551c53969b0b4343c3c78df343582e2f9d2f6f9d1c60095d23a79edb6a7e66f93e057f98817647dda02f932973711c2cbb1a73e94037fce17fc4fdc1771bc427fb33caf07e61dfa2dcd88187726625244a1aaf3f7c0fec2909c378b4564fe52340833990810d1895e80502382271f73b6fb55c7df9a425f1c9cc7eca1b96a2b7b12f3f0b2f684b459be96f7f3db7a30d4f51e57bf8e152b4ed4100f59e84ea7132bfad558f1c739badd60a3c1abebdff5a53ba2323dd77833e5acd28d59ef5c15416ae53bca35a01ebda7414986936b4a01f5035ae5090403cecf1acc859cdaf16ac06e42c261ac99cecba5c66f238f0cde58ef387e483aa9dd42a3c5263b6afc2fb40e5abe49a6dba1a3603e5c878390d8bf64d7d249922f949d54f55929d630232e178b29e2750903cecfd26bb56c6444069f7c157928bfe145a225add53fd2ef5a77d471735f1093224f3f3473f9e6033138a296bc1a4192b6
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153219);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/22");

  script_cve_id("CVE-2021-1440");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx04451");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xrbgp-rpki-dos-gvmjqxbk");
  script_xref(name:"IAVA", value:"2021-A-0407-S");

  script_name(english:"Cisco IOS XR Software Border Gateway Protocol Resource Public Key Infrastructure DoS (cisco-sa-xrbgp-rpki-dos-gvmjqxbk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a denial of service (DoS) vulnerability in the
implementation of the Resource Public Key Infrastructure (RPKI) feature due to incorrect handling of a specific RPKI to
Router (RTR) Protocol packet. An unauthenticated, remote attacker can exploit this, by sending a crafted RTR packet, in
order to cause a DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xrbgp-rpki-dos-gvmjqxbk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd29f3b9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74637");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx04451");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx04451");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1440");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(617);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info['model']);
if (empty_or_null(model))
  model = toupper(get_kb_item('CISCO/model'));

var smus = make_array();

if ('ASR' >< model && model =~ "(9K|9[0-9]{3})")
{
    smus['6.5.3'] = 'CSCvx04451';
    smus['7.0.2'] = 'CSCvx04451';
    smus['7.1.2'] = 'CSCvx04451';
}

if ('CRS' >< model)
{
    smus['6.7.4'] = 'CSCvx04451';
}

# 8000 series fix is 7.3.15, which is immediately after 7.3.1 - so add 7.3.1 to flag in this case
var vuln_versions;
if ('8K' >< model || model =~ "8[0-9]{3}")
  vuln_versions = make_list('7.3.1');

var vuln_ranges = [
 {'min_ver': '4.3.0', 'fix_ver': '7.3.1'},
 {'min_ver': '7.4', 'fix_ver': '7.4.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['rpki'],
  WORKAROUND_CONFIG['rpki_configured'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvx04451',
  'version'  , product_info['version'],
  'cmds'     , make_list('show running-config router bgp', 'show bgp rpki server summary'),
  'fix'      , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions,
  vuln_ranges:vuln_ranges,
  smus:smus
);
