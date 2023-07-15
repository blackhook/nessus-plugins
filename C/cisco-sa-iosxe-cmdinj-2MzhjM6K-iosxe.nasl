#TRUSTED 441908f611df2aae23694c8a4d8ca6a2db7c40f6822a3d503b09aba9cd1410bc597cc782fa8e070c117eb9c6a626b112911d4fabccd4405c4959f7c9d6acbed7415e697e9b26c11a12acf2bd857d668750e1f448c1c9f08e0da06d3f8933f6bd1b6c6f903fd3b4aa63d499e4abfa944891b46f65a47a80ba6e3b1a79d694835e7d66507d68e64ef94f107cb6b6f578b1cfefa5ac944e6be02190af94b1874b79c808c51c67dc8b0be600a5f85f4a212cb0d57bac892528c442194692bb5fd0e9ea0d1232f185142c62bc0a4628a7d6ff28baad5ad371e88faba26574ebcb836935af92bbbbc72f5327f08158d54631a5f9bab4732275982bb3e2cb56246f04f0897ae19a342e10ca5f2f62bfe13a7e02f251105c6f9eba1e1f4d9e96c7721362b5688129a83d604a2800fd8196048c2ff41bedf326619c32618a77c72c256051c8c85d58c15203c683215e887afc9e7dee9140275ded95adbb95cb4641c1c58de04db218f0a0517c6431d1b23031f96e069bfc4df608734d87bf8a60fed0c123b439c50e30a50fe9ec483460f170b874685be5e91c15ab90744229a8141d3b858e711c759d6eaeec270dee58034b1ff55a1676001bc44cefd6ae392548891e962b61020af075f5d95399644a7fa08802d51a259f26242b2d5407f3ee6316a73a5a7d248b22d9904371a46a489c55e4998506cd511e415924917889acdfdd0616
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141193);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3403");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs07077");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-cmdinj-2MzhjM6K");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Command Injection Vulnerability (cisco-sa-iosxe-cmdinj-2MzhjM6K)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a command injection vulnerability. The
vulnerability is due to insufficient protection of values passed to a script that executes during device startup. An
attacker could exploit this vulnerability by writing values to a specific file. A successful exploit could allow the
attacker to execute commands with root privileges each time the affected device is restarted.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-cmdinj-2MzhjM6K
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eae30938");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs07077");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs07077");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3403");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/06");

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
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1t'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs07077',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
