#TRUSTED 6d8f0d10584188f8ff69c3b0cce71b7de983bca6f1e059f448a74b92db7f6d9be30fdeb45a8dfc53d783930f6da605399f6be2834c5404d90ebbd418fb0f89b4ac827d028c88ba61a831fb66a3860264bfa26a5ad585adc8ff5c4cc5c9b0510729c14910febdc51f62e8c18b10f8c73c23dd58e15d3d16abd8b9a1c56c03547737dc1df9f24168b908fce5ada96d05f08e2ca72d9103a3c90ef69c09c96b6f87c5ed541f0bc23952bcda386e9c5bfd61ef99cb351e34e8727080f7ce1fa7659ab1881181f42cefcc80814106a976063c5d964f7713812a8e353692a2173f03f14a171e65bf617f5ae225bc3dde3c94589061efcde9518d5f818cf36b57685fb3d3933a52e7af2cd1b40027662bcac87bdb5b711eff8c4764aaf6e81ae7dfcbe182602ef6a054dd1b57c0a755ee0f4e9b59ded8713efaf78c7167be045ed7e1a8efde9bb26ae39120730fc86eac61d085161be2722932d82582526509a75168ae9ea65f318f8f9b055372bfc95189d9d6cc482227c3c5585b3933e380249ae0b200d3a97ae511c48e5bb2f276e3d4e767b17661c224babf63a6af42492cdbffb51a75fe1b13f11cd23064b1b0e007ed4090851c7b67507452ca3e9d1583bc1e5acc03292b4cc7dd8b7744f2330ae1deee665a009d755ec52897ef434b869c5599bc73a901f57e30d1f4332db3aed7c7a7052e929e3b11e0d84001bcc07573b675
#TRUST-RSA-SHA256 0222f624ced10ee78b242f23091493ba5181993831d6d5256077b431c80dd471fb75823189283b332c84718ee798600fe8e9f5017ee53a01099a64c1b86a86981056f69dfcc73707db9c8b5fc38b0d3d0f6b1e92ab8a9ff2b285aef6dfe69a4d3620c8c4811b1cfc75ef13590dedb89a96eb62c0ad3df6dba8a6d015f1a9eb545cd0ca202ac3842151787ddab547c1442b653e436283f7af152ff22fe01d712b8589e8159c14255f8ff5c856568d2469fceadfce14083fe04d0bd1f0c119332e89b3576ee5e490b563fbb7ed0e6b13703be4b8d5959e391950cc3f9a72dd9e4b016f6a48b9d27114c58b53cbf0049b8f736e0a74ed3cf77bf5b3b5788c8bc75a835075d991bbb2a35caa1e8848c47c24541be68f3ebdd0e8fbe8198fed16339d4828f57fbab33ba80c0c0f32f3e100833aacfa50661a6620930da18800b9426b7202bf9a125bb0b1951664a9b112b9d5d8d855747c08a8d8622817cc7b3f1a8df1da76e80d3b3dac2472da0190c351d7ef005f4cb33a6bd2de203702d2befb9611c009727188b73426e4a71a91bc5876a7683de065f33d94bd6debb96321c06668ac9a051cfc6fc5a2a4a9af72a2535fcccd63f440917a2cc2aa75b1c09946b0c51600ca334ac1a9a31eb7512bd699d7b4bae62ae042a425fb0393a16fdb01e83140fa17043794e5cda8d1b03c1d3501b853762aa8409ab330ec065893fd95d0
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166016);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/29");

  script_cve_id("CVE-2022-20915");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa41184");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-6vpe-dos-tJBtf5Zv");
  script_xref(name:"IAVA", value:"2022-A-0390");

  script_name(english:"Cisco IOS XE Software IPv6 VPN over MPLS DoS (cisco-sa-iosxe-6vpe-dos-tJBtf5Zv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the implementation of IPv6 VPN over MPLS (6VPE) with Zone-Based Firewall (ZBFW) of Cisco IOS XE 
Software could allow an unauthenticated, adjacent attacker to cause a denial of service condition on an affected 
device. This vulnerability is due to improper error handling of an IPv6 packet that is forwarded from an MPLS and 
ZBFW-enabled interface in a 6VPE deployment. An attacker could exploit this vulnerability by sending a crafted IPv6 
packet sourced from a device on the IPv6-enabled virtual routing and forwarding (VRF) interface through the affected 
device. A successful exploit could allow the attacker to reload the device, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-6vpe-dos-tJBtf5Zv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b86b041f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74745");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa41184");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa41184");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(115);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# If both mpls ip and zone-member security are displayed on the same interface 
# and address-family vpnv6 is configured, further verification is still required.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var version_list=make_list(
  '3.16.0S',
  '3.16.0cS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2bS',
  '3.16.3S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6S',
  '3.16.6bS',
  '3.16.7S',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.16.10aS',
  '3.16.10bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.6.9',
  '16.6.10',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1c',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '16.9.6',
  '16.9.7',
  '16.9.8',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1e',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1c',
  '16.11.1s',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.5',
  '16.12.6',
  '16.12.7',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1a',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.4',
  '17.3.4a',
  '17.3.5',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.2',
  '17.5.1',
  '17.5.1a',
  '17.6.1',
  '17.6.1a',
  '17.6.2',
  '17.7.1',
  '17.7.1a'
);

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa41184'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
