#TRUSTED 35acbc0db081c88fabed4203a1b6bd8621ebbdfab2706c5eeae1531f129b3935464659a926f24e47180645d1340169e1e72bd207fc4a3dd6a340a15087f454fadf3b242c2869b6986fb50f4ef5ede0b3b9c2e8162d1a6d082199d2c469cea77bb7472b2a0d8cc88bb84b42b43b6399a043b4b43f70072ee431246cda2dcbc1e086029152ec00da1afc168143c60a6e4ad3339fc176a77af0acff961ac2ccb0d92fb00051a301ff1993296287577426c18582609068a8a463770653d91adf66047c94af465ae40459c0265d200f1ee63405fbf611f81a2e63b3d0d46309b43742336d46be933eb0d5bed73b1dceb71e8745f5e8426ba59bfd1525a45d6e7ea8c788ba767598cedb5b87c4c43bd800894d9610810e164125c71277fb45fe02a676d8a7c4986502ca450d25e12fc46ff19c68a9ac526770021278b0ca0d9a8128f080c6f6ec790b37cca262ac6552634bd915c1f437c0cb8a58137e024641313e870a6e8ac3a320073cc274fc6a642563a9d20538190ea204c2ca23dd1a32fdbac9f129dfa6b1f362998597789239249ba7e801934175515b26f04ff9094e0869230bb4b672b1e344fe3148bfd68c15b448bccf8b378530085476c88bc7d7e8b1a4e1164ac3a4c13e9cd5e9412a35588a157eeef8a4fee607499cf613a59040d45219c2e891eb01c7df34f9f51b0e7817f73b5b1c16d1d3e166da73ef35d649d77a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141231);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2020-3479");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr81264");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr83128");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-bgp-evpn-dos-LNfYJxfF");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS Software MP BGP EVPN DoS (cisco-sa-ios-bgp-evpn-dos-LNfYJxfF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a denial of service (DoS) vulnerability in the Multiprotocol
Border Gateway Protocol (MP-BGP) for the Layer 2 VPN (L2VPN) Ethernet VPN (EVPN) address family. An unauthenticated,
remote attacker can exploit this, by sending BGP update messages with specific, malformed attributes to an affected
device, to cause the device to crash.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-bgp-evpn-dos-LNfYJxfF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90954329");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr81264 and CSCvr83128");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3479");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '15.1(3)SVR1',
  '15.1(3)SVR2',
  '15.1(3)SVS',
  '15.2(5)E1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(5a)E1',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(6)E2',
  '15.2(6)E2a',
  '15.2(6)E3',
  '15.2(6)E4',
  '15.2(6)EB',
  '15.2(7)E',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.2(7)E1',
  '15.2(7)E1a',
  '15.2(7)E2',
  '15.2(7a)E0b',
  '15.2(7b)E0b',
  '15.3(3)JK99',
  '15.3(3)JPJ',
  '15.4(1)SY',
  '15.4(1)SY1',
  '15.4(1)SY2',
  '15.4(1)SY3',
  '15.4(1)SY4',
  '15.5(1)SY',
  '15.5(1)SY1',
  '15.5(1)SY2',
  '15.5(1)SY3',
  '15.5(1)SY4',
  '15.5(1)SY5',
  '15.6(3)M',
  '15.6(3)M0a',
  '15.6(3)M1',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.6(3)M5',
  '15.6(3)M6',
  '15.6(3)M6a',
  '15.6(3)M6b',
  '15.6(3)M7',
  '15.6(3)M8',
  '15.6(7)SN3',
  '15.7(3)M',
  '15.7(3)M0a',
  '15.7(3)M1',
  '15.7(3)M2',
  '15.7(3)M3',
  '15.7(3)M4',
  '15.7(3)M4a',
  '15.7(3)M4b',
  '15.7(3)M5',
  '15.7(3)M6',
  '15.8(3)M',
  '15.8(3)M0a',
  '15.8(3)M0b',
  '15.8(3)M1',
  '15.8(3)M1a',
  '15.8(3)M2',
  '15.8(3)M2a',
  '15.8(3)M3',
  '15.8(3)M3a',
  '15.8(3)M3b',
  '15.8(3)M4',
  '15.9(3)M',
  '15.9(3)M0a',
  '15.9(3)M1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['BGP_EVPN'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr81264, CSCvr83128',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list);
