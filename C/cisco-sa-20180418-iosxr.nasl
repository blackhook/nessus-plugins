#TRUSTED 79873e8254c65512cc2c019197f1e3f057a0346cdf34027271bbda6d88cd96377ea36a356d7b342b0f3ae1ef2552cae736f1b4f33f5338b23d6f63cfff29dcdaa29b1bb280a675d8c00bb638c0205b52275e8a6289999db65a25262b3e16ac9ffdc528602fc355b632f07683736c2737cc6d0e092894aadde7fdd936e8e91c3688b2c927c8895d253109d8529315d5981948dae9e0ad9c0a792e4d48e7510989964fe1ee283a0387d913b89db9366025eccd014643cc861b205ae7866234badea6b83a1d62aa84eebebf565d0a9a391b65ad3e5e0f0b73e66802985e87ff0a7700c2caf1f12d7eb4cfae1a7d6159fc01e4f97ee3e8a91c27c6bbba1c23d0e269a10ecbde7165aeb89812aa10ede0265c115ca78712f5c51b5642cda075e134292571025b98c8ff01418cdb8c1cb8c7cee72fd24a9cfb692a21f308d1590b88acac22f6bc0362841ec6fc1f88ae82e6f8de1c0db33e043d9805c2ab7fcceae73549c1c1422e2e8b4d8d454073571a26d4a45bfe8b1d50bc2351a4740025444676116234e697eb4b815a35bc286e2fa4e0211498ca37c874cdff162f6cc1d544be0de35f4d5e5d4f46427d26864c8bcd31ea1a519ad29098c2390a95714f56504c388e0f68ae082335a577b0ee6e9ecce02582678cf146d9697db59899fdf4553ea60028da1665a0ad45d04941a20f293165073e7db858ce5b10f638d2da59e8f5
##
# (C) Tenable Network Security, Inc.
##
include('compat.inc');

if (description)
{
  script_id(109393);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2018-0241");
  script_bugtraq_id(103929);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi35625");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-iosxr");

  script_name(english:"Cisco IOS XR Software UDP Broadcast Forwarding Denial of Service Vulnerability (cisco-sa-20180418-iosxr)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XR is affected
by a denial of service vulnerability. 

Please see the included Cisco BID and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3baec20c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi35625");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvi35625.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0241");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');
var version_list = make_list('6.3.1');
var version_range = [{'min_ver' : '0.0.0.0',  'fix_ver' : '6.2.4'}];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['ipv4_helper-address'];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi35625',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list, 
  vuln_ranges:version_range
);
