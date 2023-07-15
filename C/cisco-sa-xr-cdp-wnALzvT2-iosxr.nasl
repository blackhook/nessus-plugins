#TRUSTED 278bbcc44218ee819d255858c7b4ff4198775233dc371fa0e85530e864a9ff3547765f62cfa387c5b0feb0ae42f0e0518f3df8db48ea5e483191b4b49a32403c759618c68e0e36c20abc02386a679bdb6b12443910792197e9dc162fd913573fcb4e253715d7e30a9e20e629f4502b62ad40801b7107f2c05973dfc51dd7939d0203665c0de47cd88088a4ff782b2e49df9e25cd3ae0f80cf45a7d58613f1a48754e52fd5dc6680e60d4d12bfa26190dcb33e7a208e598160eea67c2970d0962f5363d8f73f09a11a82853077daf9fa13fdfa2989a8486b85e077e3844da47139c9df623dc976ec615d767039192a17c2c544eabfbb058e77be5877cd0b47e6b9d08bd7c4416deef47b9bc0699b940b2db396eb01dc6b156c6f6d4ceb1d14df0ef2a5b74ce2fb9e0afafeace8224057772bb1212d6c6f8972d901c4e604e1f05b01c9a25591b8c35a22265c0ae7e08b08d88b9c1e92130d662847ecfeafdd958d2c391388b23d6022156f3eb7ec93867fee557924602e3a8c6952fb2a9d8b2ed42994fe2396458e58e513087be41dcd23f41edef468a46074da2dfc88f8bf59feee46b4edfb9cef85bb94e3e4f77b1e5fe6640fcc16429669612010991b5f66aeef33dbbb71cc35102ab86b9fb015273ed23b4c9ca5cf3a8bdde4af7eac1e65704ed96a950d0a7fbcd3c04cf24d5c048139ff0464ee748d490d2c90c0d707fe3
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165241);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/19");

  script_cve_id("CVE-2022-20846");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb23263");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xr-cdp-wnALzvT2");
  script_xref(name:"IAVA", value:"2022-A-0380");

  script_name(english:"Cisco IOS XR Software Discovery Protocol DoS (cisco-sa-xr-cdp-wnALzvT2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability Cisco IOS XR can allow an unauthenticated, network-adjacent attacker to cause a denial of
service (DoS) condition on an affected device. If the Cisco Discovery Protocol (CDP) is in use, an attacker can cause
a heap buffer overflow resulting in a restart of the CDP process.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xr-cdp-wnALzvT2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fe1a143");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74840");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb23263");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb23263");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20846");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var vuln_ranges = [
  {'min_ver': '5.2.2', 'fix_ver': '7.5.2'},
  {'min_ver': '7.6.0', 'fix_ver': '7.6.2'},
  {'min_ver': '7.7.0', 'fix_ver': '7.7.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['cdp']);

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_NOTE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwb23263',
  'cmds'    , make_list('show running-config all')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
