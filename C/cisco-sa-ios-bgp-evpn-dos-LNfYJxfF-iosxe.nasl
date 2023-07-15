#TRUSTED b2ac8175f60c4b5872bbc945b70733771751efd3f810179834ae5d01665dde4265d1aef45cc4628adfda1d403d4aca4039ad2399365dbbad0a2726351f8c81177a1ea8aa0a1818872e911522d0cfded93a0105350288a6ef0893c8afc57762f19e97e68ff4bf951e83a57ca2335b48b44070ba49182bee3ae1630607541569fb4d7601b35cc81aa30dee1143604691a4cb5f0bfed0a105f8db5cbfe258050762afa447af9932272de09c5e512cc984909884a6d60bbc30fa744fa6efe8ebbd5e2ac254ccd9756928e7a9f5504e182767928b2586b092fda89d03a5986498460249f8197d9f1d822b4d37e41a052c28c26621145dfa46827c3b6600af477d7f75614064256fb47d198db8b716581bdc3c3233c981bcbba5044c91dd70b9a729ca487d50612ae1c9aebc0c9b751aa83c87442cb1f7d1bf2c3852818cb2b9193dc865cfbee2332fc0441901c2b1f9a5e193c260307f49b38f2d47ef2c879b3f20217a3820d6a70b1a5dc83a64ddf66906301479750f886a2e89c3e5c7741a9ad570e5cea1c1283d303aa4011e04eab5d7b350bde42deda2cd1a9955359f19a28ffedea04d14558d9ca05258087100c6e7dac88f2a32b5151c0416286f3e7b15d8b562d4052da0d834ec0c16e3a865b70e81fec8e0845949d48da4ea189eef59dd2c101d820be5063a0c4fb3956858b1439c1c1c8f119872be2fd32d077d98d614e1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141230);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2020-3479");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr81264");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr83128");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-bgp-evpn-dos-LNfYJxfF");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software MP BGP EVPN DoS (cisco-sa-ios-bgp-evpn-dos-LNfYJxfF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a denial of service (DoS) vulnerability in the
Multiprotocol Border Gateway Protocol (MP-BGP) for the Layer 2 VPN (L2VPN) Ethernet VPN (EVPN) address family. An
unauthenticated, remote attacker can exploit this, by sending BGP update messages with specific, malformed attributes to
an affected device, to cause the device to crash.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-bgp-evpn-dos-LNfYJxfF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90954329");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr81264 and CSCvr83128.");
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.3.1',
  '16.3.10',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.2.1t',
  '17.2.1v',
  '3.10.0E',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2E',
  '3.10.3E',
  '3.11.0E',
  '3.11.1E',
  '3.11.1aE',
  '3.11.2E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE'
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
  vuln_versions:version_list
);
