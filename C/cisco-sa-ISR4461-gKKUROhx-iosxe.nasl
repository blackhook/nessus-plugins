#TRUSTED a6f30ab3b9d64da7150aab29593ae5d610a5739b348db4801e49e7e723a58c755fd11bc50ce60b6c8803f6db1b3e033e4b2b1b1c68ed9ec0af9de335cb3c4751a6901640cffa2709b2f4a0d7b93bba100cfb9bbe9dcab42308950b4fd85cdbbfb61d0088bbc519b1334d031b9353a463110bfe7a888e3906a5606a6868a6888fcc60dc69d81c0b8814da531db811097dfd2451b549adf03f7287e697cc3dc099c1d1d41d7837a9fd5edcf7931fc1bb0fc2d5a78e1c073b7f1ce2f0ad55090c37a9aa5b9d39d50d2b4c794d95740da9c7facce7ea15b357707f100ded4f083d38165d131d34a8657ea60274289664725c882773761ee726898c38ceb12966d7166a3b2cb9d548ddd70fc2863efafb0dc32eb851c4c076e9133ac369517ba90ebb2e231f17a8b318122ab34a3eed4356b9a418585ccd09e2d230292a4e6bae777569e5ccc25b65ba6fa755179f6215fa97ad5c37e0f8494fa7990ef07723c4ed85b765e4fb593c1c16e4a9a0e8fb09e05bc9a14ee4e4e161fc05ecd95ee92920cedb20b04f55363b590293caceb5294f644621c8a8e53832a0e0c2fa4f040addcd485ebd1a1c6ef3118867c69ad5b44fa29166d40a696c7971f65f14e0f94a677d722945572daa56a2b6050abed5138d191fb76521b87893daae31335e33f277fd49b536ddefab62d54492e2cda8524c34a0c9f906aa28743919767a797748142f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146084);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2020-3414");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs77143");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ISR4461-gKKUROhx");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software for 4461 Integrated Services Routers DoS (cisco-sa-ISR4461-gKKUROhx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a denial of service vulnerability. A vulnerability in
the packet processing of Cisco IOS XE Software for Cisco 4461 Integrated Services Routers could allow an
unauthenticated, remote attacker to cause an affected device to reload, resulting in a denial of service (DoS)
condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ISR4461-gKKUROhx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8f36a52");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs77143");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs77143");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3414");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(19);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = toupper(product_info['model']);

if(!pgrep(pattern:"ISR4461", string:model))
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list=make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1e',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.9.1',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '17.1.1',
  '17.1.1s',
  '17.1.1t'
);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs77143',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
