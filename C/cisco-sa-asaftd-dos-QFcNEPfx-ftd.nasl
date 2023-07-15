#TRUSTED 8002d3c2bb4b92b121e49a88b7399718eef1ff9e2b658ddf4da970c9ee21d47bd53d409970b06160fd992932acbef80b901bd9c8757ef2e90eb270ea9d5f7cb0f258a518521aaf62ae51ac44ed45af047da6a512d165f8595cd95fa44ed6fe37cc5f764ccb4d0c3866ab7b14881242a3a546ffcec596671b358438d3f57222e75fd78b77e6f7c47df4a965b6a1c1516239910d54deb2479de3ff2d67f5e2907532488de3a36477c44a98a457b949fe19fbcf92e41fba17759f02b4dc5f51c68f9605d8976e112685d1d4608772ba5620b5bdba614d9d8222199d2699f4c04150eb57c21053060e3d1dfa23c6dc16d4a7c9a6766acab7bb9616db5c9bfa89c31df9c7070f8c51d86898bb10a0d685922c7eb9414309551c6cf3aceb62fba5bfe31b59fb56d8eb647a57aff5a7b60843d62dff3b79a65c1a7b7c767b9d470daf6d156b169dd40790c1799a0acd68c6732b971df8b299a6761adc0f36feef407272b24d2c8c8350213750610849c5df043a58f95a8c4d0f187fa600c09ce1773059121398590f92562cceea9485c2208b382ce506e4f4d85e1dd85702f3b1f62a02d1d3539cf712d19945295d387bd795e9859b6e404051fb04bd754e01acfc2bca5a9af64ad7e16121769117c06db6a51e7b2f15d62774c5245d5fcbba750058bc2c149fbbd8119e5d138590006fb5c95044b7b6a2dd17f74689f06c6088588ea5
#TRUST-RSA-SHA256 595708dcc23b83f6b06a50b47c70b546b7a35c13edbc3c7cfdbca8708c96ffb2e4b7962e3e607bbfcc2284449b857d1bc95cd1d9b03ff74e666e831a601836d56f67f9ef58548f3e3e0ba47539743828f66daa15c3607c49fceaa9560b448d77a589524e7704f8ae8faf4447b675f3928db552649610b4288e527cb711751c96a3017031e6fc00eea97f3d33a255f99103d257e2047676d02e582dc976f274248f31bdab09844eb9053f0870465402451043c8e2b8f883c52b35dfc8481e75eb758237409ee1f7102362e0ee3599caba29022a5714dcbbf5f3d69274c8edca4d5bb3829616df84db54b330cb58eb49193043470f737b122d02216071cec6da30bad8335ff72f31cc76b3ae31be863270a0d6744419e84f04913fa53d1ea9924b3323283bc9b1761622385f46f4920acd34786cabbb17ed1d10541903fd8d6dcf78170ec596e3936ab566ea5ac1722168c99b1f64079ae5affbbc0d4ae92423d6a5c71f33ccdafa175ba4978d1a238f6bfa6c5b4c336c9459bc52982a41410150733ed56642efc26590f1858ac90bb23db02c4f546483ea60768b564b82dc4696e6f472a19e6dc63f34d3eabd1cc03861b0adabb7ff0d9f84e76adf9249c7c9ab8e44fe3c395bc636a66410a6491bdc400529cfd8b404aa7486ff8f1a7bb7467e06e441c5b5ae238cc7788451c32356f91043069606af608613dca5087f128ae2
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149311);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3554");
  script_xref(name:"IAVA", value:"2020-A-0488-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt35897");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-dos-QFcNEPfx");

  script_name(english:"Cisco Firepower Threat Defense Software DoS (cisco-sa-asaftd-dos-QFcNEPfx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the TCP packet processing of Cisco Firepower Threat Defense (FTD) Software 
is affected by denial of service vulnerability due to a memory exhaustion condition. An unauthenticated, remote 
attacker can exploit this by sending a high rate of crafted TCP traffic through an affected device. A successful 
exploit could allow the attacker to exhaust device resources, resulting in a DoS condition for traffic transiting 
the affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-dos-QFcNEPfx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e0b20a5");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt35897");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt35897");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3554");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver' : '6.4.0',  'fix_ver' : '6.4.0.10'},
  {'min_ver' : '6.5.0',  'fix_ver' : '6.5.0.5'},
  {'min_ver' : '6.6.0',  'fix_ver' : '6.6.1'}
];

is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

  var workarounds = make_list();
  var workaround_params = [];
  var extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  var workaround_params = WORKAROUND_CONFIG['fragment_reassembly'];
  var cmds = make_list('show running-config');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt35897',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
