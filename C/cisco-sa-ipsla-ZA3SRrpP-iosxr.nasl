#TRUSTED 021b4150e1ad9411967b2956d72e2a1d8222fff1ff3b29e4bb1da2ff81e70030a83d79f10db9a930651a1c0f7792678f77b207c7779c26de644ff9872ee3073242b276de196b460916a8b570697683efd0be6e276eb299e7334e3f8c865b8ab0a6fb952c8b7e8c829fa242b37d84457248377e295f72a2316603ab5cde481f8635d9256c8b70ee34b5f109ef3fa19679ab8f723e0e111460202e0c2a80a83e0d08fa9ff9c40b146976b80b9b9939afba47a5b1d0477de5a52a408f959de60445333aa2833a74303ba007eced4bbaccc693a6a16629bfbddf55ad1c4788f774bdd3960489f36ce32299ef14cc5e087773a16e7d176c4cbc09f3b3667e5673d154d6b67d6f69908095d5f41f3ad7adb96c0fc90feb256e2be73d9ca1ba444066525e260a969587238be36bac7f37f7838f9eae8451c6de9e6ac50b2559ee6397ea891053d326e408435d91d105995b951357bcf34cb51ae4e63e8dfce3d60e24bcd4c2dbcc8247c0e53b92fd0796d530b07b73c6825db0fa10230caba997bd276efda2aa3a473b5dff0a667d9ba4b4518a70709b42baaa6edf83aed3e3beff76cfb33f969bd4ff14199fc032739f79ed1ed5e082e3200dd7806cfc82584705ab3001f7a9772bff36fa5df4f84813bcc270f7988c6dcf164cb06eba28a6c57747f1f69316fe78aee1c3a6356466b7b6e2c491fd02b5694ff4b0a1ff3cfe38cee51d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153206);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/22");

  script_cve_id("CVE-2021-34720");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw32825");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw61840");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ipsla-ZA3SRrpP");
  script_xref(name:"IAVA", value:"2021-A-0407-S");

  script_name(english:"Cisco IOS XR Software IP Service Level Agreements Two Way Active Measurement Protocol DoS (cisco-sa-ipsla-ZA3SRrpP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability in the IP Service Level Agreements
(IP SLA) responder and Two-Way Active Measurement Protocol (TWAMP) features that allows an unauthenticated, remote
attacker to cause device packet memory to become exhausted or cause the IP SLA process to crash, resulting in a denial
of service (DoS) condition. This vulnerability exists because socket creation failures are mishandled during the IP SLA
and TWAMP processes. An attacker could exploit this vulnerability by sending specific IP SLA or TWAMP packets to an
affected device. A successful exploit could allow the attacker to exhaust the packet memory, which will impact other
processes, such as routing protocols, or crash the IP SLA process.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipsla-ZA3SRrpP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c47a1c9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74637");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw32825");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw61840");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw32825, CSCvw61840");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34720");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(771);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/10");

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

if ('ASR9K' >< model)
{
    smus['6.6.3'] = 'CSCvw32825';
    smus['7.1.3'] = make_list('CSCvw32825', 'CSCvw61840');
}

if ('NCS' >< model && '5500' >< model)
{
    smus['6.6.3'] = 'CSCvw32825';
    smus['7.1.2'] = 'CSCvw32825';
}

if ('NCS' >< model && '540' >< model)
{
    smus['7.1.2'] = 'CSCvw32825';
}

if ('NCS' >< model && '560' >< model)
{
    smus['7.1.2'] = 'CSCvw32825';
}

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '6.2.3'},
  {'min_ver' : '6.3', 'fix_ver' : '6.3.2'},
  {'min_ver' : '6.5.2', 'fix_ver' : '6.5.4'},
  {'min_ver' : '6.6', 'fix_ver' : '7.2.2'},
];

var workarounds, workaround_params, cmds;
# Only TWAMP workaround check needed for versions 6.7.x >= 6.7.4
if (
    (ver_compare(ver:product_info['version'], fix:'6.7.4', strict:FALSE) >= 0) &&
    (ver_compare(ver:product_info['version'], fix:'6.8', strict:FALSE) < 0)
    )
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['ipsla_twamp'];
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['ipsla'];
}

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw32825, CSCvw61840',
  'version'  , product_info['version'],
  'fix'      , 'See vendor advisory',
  'cmds'     , make_list('show running-config ipsla')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
