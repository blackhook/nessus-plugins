#TRUSTED 6171aca4e8396af90ec0e8bfc815b5e79b3f910eda0f748bb81f632f4ee22f874dff382bd8cbf557502799d27776d618a4e0bd2d2dd6db8eecb9fb07d5c6da7f6e784458f6c8b860c1b3e3bb65ec30898cd15d9fb5abd58b356292898b6f557eedece23c0768bab75dc2e9ebdf4c20aed2b79d479e55b92f9362d64dce2929ddf62310f5a1dcbb48c0366de9f50018b34a1f52e9eb9ee2bfe48bd775f8da00e56018d7b507d16db65d658a64c63aa15109ab0824617a9b07e3d29dcd218437dcc7c8c9fcc6778ba13ee6c3a1813f632cd9d9a1f1dafc5972b4d852070bea4aed5d8b6cdb1d3eca97a9047df71620f6432c0491ccbe9bdda31db64fea85442f5101bf51f193571cae29b53ddcfd570ae6d7e8fe0ae69355096b6e720a5e3e789176ce1acda53569435359c40e3ba01ea1468f77b31e2ade45b9d85199958dbf98e6f70f4cec276e27b25ce25cf33b8f0f7ba1b4e02eb09e86ddd1215c426a889191f6cedd91554fa416bded79c492ab8a6f23427d2ebb521847462d28d8ec6aaa3425e6df653d2058e0baebf8c32541eb477a5193c824205d404b71c626b8285a22d20c1a846bcebb68c3e466b08c0c770928ee91149800cb94d986f38c5d5a5c8ccd034118b1726d5313c9284b39919dab5453ef9299a3d5abe82db96279ca4b27719a24310f57bf4b6084ad0cfe61c2e5ebf2b1961914d6c04a8b00e9ab235c
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149957);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/27");

  script_cve_id("CVE-2021-1230");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr59494");
  script_xref(name:"CISCO-SA", value:"cisco-sa-n9kaci-bgp-De9dPKSK");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches ACI Mode BGP Route Installation DoS (cisco-sa-n9kaci-bgp-De9dPKSK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Border Gateway Protocol (BGP) for Cisco Nexus 9000 Series Fabric Switches 
in Application Centric Infrastructure (ACI) is affected by denial of service vulnerability due to an issue with the 
installation of routes upon receipt of a BGP update. An unauthenticated, remote attacker could exploit this by sending 
a crafted BGP update to an affected device. A successful exploit could allow the attacker to cause the routing process 
to crash, which could cause the device to reload. This vulnerability applies to both Internal BGP (IBGP) and External 
BGP (EBGP).

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9kaci-bgp-De9dPKSK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e39258be");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr59494");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr59494");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1230");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(233);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/aci/system/chassis/summary", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "^[9][0-9]{3}")
  audit(AUDIT_HOST_NOT, 'an affected model');

#  9k in ACI mode
if (empty_or_null(get_kb_list('Host/aci/*')))
    audit(AUDIT_HOST_NOT, 'an affected model due to non ACI mode');

var version_list = make_list(
  '12.0(1m)',
  '12.0(2g)',
  '12.0(1n)',
  '12.0(1o)',
  '12.0(1p)',
  '12.0(1q)',
  '12.0(2h)',
  '12.0(2l)',
  '12.0(2m)',
  '12.0(2n)',
  '12.0(2o)',
  '12.0(2f)',
  '12.0(1r)',
  '12.1(1h)',
  '12.1(2e)',
  '12.1(3g)',
  '12.1(4a)',
  '12.1(1i)',
  '12.1(2g)',
  '12.1(2k)',
  '12.1(3h)',
  '12.1(3j)',
  '12.2(1n)',
  '12.2(2e)',
  '12.2(3j)',
  '12.2(4f)',
  '12.2(4p)',
  '12.2(3p)',
  '12.2(3r)',
  '12.2(3s)',
  '12.2(3t)',
  '12.2(2f)',
  '12.2(2i)',
  '12.2(2j)',
  '12.2(2k)',
  '12.2(2q)',
  '12.2(1o)',
  '12.2(4q)',
  '12.2(4r)',
  '12.2(1k)',
  '12.3(1e)',
  '12.3(1f)',
  '12.3(1i)',
  '12.3(1l)',
  '12.3(1o)',
  '12.3(1p)',
  '13.0(1k)',
  '13.0(2h)',
  '13.0(2k)',
  '13.0(2n)',
  '13.1(1i)',
  '13.1(2m)',
  '13.1(2o)',
  '13.1(2p)',
  '13.1(2q)',
  '13.1(2s)',
  '13.1(2t)',
  '13.1(2u)',
  '13.1(2v)',
  '13.2(1l)',
  '13.2(1m)',
  '13.2(2l)',
  '13.2(2o)',
  '13.2(3i)',
  '13.2(3n)',
  '13.2(3o)',
  '13.2(3r)',
  '13.2(4d)',
  '13.2(4e)',
  '13.2(3j)',
  '13.2(3s)',
  '13.2(5d)',
  '13.2(5e)',
  '13.2(5f)',
  '13.2(6i)',
  '13.2(41d)',
  '13.2(7f)',
  '13.2(7k)',
  '13.2(9b)',
  '13.2(8d)',
  '13.2(9f)',
  '13.2(9h)',
  '14.0(1h)',
  '14.0(2c)',
  '14.0(3d)',
  '14.0(3c)',
  '14.1(1i)',
  '14.1(1j)',
  '14.1(1k)',
  '14.1(1l)',
  '14.1(2g)',
  '14.1(2m)',
  '14.1(2o)',
  '14.1(2s)',
  '14.1(2u)',
  '14.1(2w)',
  '14.1(2x)',
  '14.2(1i)',
  '14.2(1j)',
  '14.2(1l)',
  '14.2(2e)',
  '14.2(2f)',
  '14.2(2g)'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['bgp_sessions'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr59494',
  'cmds'     , make_list('show bgp sessions vrf all')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
