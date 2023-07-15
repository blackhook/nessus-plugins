#TRUSTED 5bdff51577d102259b8c2be2b60b3522c5d97b092ef9a35b541986f4a68c8aafb43075eba5de986462a6ae9b9df18ac40daa0feb2f506cbf9737a3d35a8132d4a0f6d386e7392777f35168508441a785161caa5fbd473b8be2d81d279fa3feee76c1a7ed78e774882c8deb14f968796090944bce858ff2be93247609e85bde1a4c1bd6b9c31c9e4a0ddd40e403f798f4be75a5e1d53ab66ede9b14b04bb79a2a9756e43c4a93301ca68ee90c1cfeade819fb9cb74b984a7d0d015950de67138d43c6a7ec21f86d042a98d3df339b64f92d9008f8e91677d9e0322913a2a5e56ebdf7cd6f329a11af132d74c5851a384f782e82e541a4ae023204f2c6d925b5b224945409ea3d9e9c8898790e86b7b36b12ebfa1b511b361aaf8d165e36571a112a8ae897e05593d20291ac78cc3309e80abbbac5018066867946b9f5b59597490a208cc5b5775c026a7cf86f8ab7c308ab75ba12d316b944019d07171141556a9e1126c681f7ee3899693f34eea5499aadec0025c9598c6c56345d8fb9a8242aba416c0313109e277b27dd14e6c1332369613093db7186f993eaa6edc81a60aeff8c695f75a2b629aa2e97e0cedd257693e5d9176e78804744b20ab889403814adac88feb8363e0e7b6039947abb6f2eab0a52cf1df4137f9ad786d77200f5409ff8d8accb7c4a67baf257375ecfcbe10bb22ecac18e55c542ac96b5f97401c7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140189);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id("CVE-2020-3397");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr58652");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxosbgp-nlri-dos-458rG2OQ");
  script_xref(name:"IAVA", value:"2020-A-0394");

  script_name(english:"Cisco NX-OS Software Border Gateway Protocol Multicast VPN DoS (cisco-sa-nxosbgp-nlri-dos-458rG2OQ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the Border Gateway
Protocol (BGP) Multicast VPN (MVPN) due to incomplete input validation of a specific type of BGP MVPN update. An
unauthenticated, remote attacker can exploit this, by sending a specific, valid BGP MVPN update message to a targeted
device, in order to cause it to unexpectedly reload, resulting in a denial of service (DoS) condition). 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxosbgp-nlri-dos-458rG2OQ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23245ed2");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr58652");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr58652");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3397");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "^[39][0-9]{3}")
  audit(AUDIT_HOST_NOT, 'an affected model');

#  not 9k in ACI mode
if (!(empty_or_null(get_kb_list('Host/aci/*'))))
    audit(AUDIT_HOST_NOT, 'an affected model due to ACI mode');

version_list=make_list(
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(4)',
  '7.0(3)F3(5)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(3z)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(6)',
  '7.0(3)I7(6z)',
  '7.0(3)I7(7)',
  '7.0(3)IA7(1)',
  '7.0(3)IA7(2)',
  '7.0(3)IM7(2)',
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '9.2(2v)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.3(1)',
  '9.3(1z)',
  '9.3(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat':make_list('address-family ipv(4|6) mvpn', 'feature ngmvpn'), 'require_all_patterns':TRUE};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr58652',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);



