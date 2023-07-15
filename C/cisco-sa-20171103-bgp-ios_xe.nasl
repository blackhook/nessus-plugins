#TRUSTED 6e72c020092a2d3f065c310799f67a52f4e4084742b3224c41f09f9fcbfcfceb541e9dcfda82cf05bed9b6822c0833d1b7bd1207254eee26fe89b2c3ca616e58c986a42c4834a431f0ccc30d7083fa2e2415010e29f124cdba35050262ba838fb65f9a6c7af0f72e1ab97c4715f1ea1a991137dcfab8ccc215c7209a77d68b84d3513c03699995086e989052d10ee1b8fd014c19e38f4179edcc30c548d27e0d9bee81e0fdda39e157a0a6d3060d0adcf67d2f93cd6a9afd373aba1f3bab8172af906ddfbc0cac843f6c48ad15c43c8a4c2058b2ad312686fc0eae12eb47f39e87e8424a1608bfe1da5aaa8c76d279459323d273bafe2bae03eb6dfc52abf9939aa066121d0cf7acd08beaf124c8feb10bdd5a4e374fd3857f5b7fea58f9fa5c15bdf5cea80c9678352350a4486ee269281f26a35090b04786ad7fa82d1554fbf8807bde45d2a5838b2d6db6a06dff56d6fbeb2f28d21861e877afeb9269ff8ae984814cd87ccdadb00ff5a80cf02128aaf8c8777a79615f316def9e7fb4880bb144b31ca0d2bf27b82991b48ad691f0b1b67c51b3c9abf82a2d6dbbd8733e1736c97b50c754144ab451817ee97ce667c943745aea376bf11dab651a25e6ab52ce07e33466142594b7e3234f754dbc6d5db814f1ae9ed19ea7d19392f7704943b96e7ae639181128c48cab996cb38cb0cd787e1c0ead887f89b2d704e049aa29
#TRUST-RSA-SHA256 1ad4d2c3d4a05833ac0e49f6e40bc47f0c6bd55582c51a91784d2bbb75d9e47dd0103c8354e132c7ada029260586fc8e113b215a18dfae37bbf3cda33aec8f7936c1fe00e64aa6f5965b35a18c75bd75415e3bc72621c0a54ca4db0d24d90640b9839b39a470541fa585b70d72eaeaa118c719959b723f45511f2bf5d7dc6594d5e8fe027c823c6b595f5021f4a0795ee4442ed8724db47d7b3c94f2f75c35595cf56707908010cca3d08aa2d175b18c346098a7511ec143cf64278f9b4c6668fb55388a440ea92102f4350e6b2f682133f6cd0b13b4cfb7d85acceb51f906aa017e3e388b12300912fbf8b80e0f85e450887902ef3afe411292f3ea5baf3f8202c4851c0a2c699d375465d42c204eacfdc940cff508607d2fd4b80f9fea4f4b554bbca544d5458f1500c49298e7f32e711a198973053c7b7c55f891c2c4b335cf717d5c27a4e3ba414706066478b44a0c45224cf09037d53e3ad3d26858acb378f0235a3856e2d694d8a1f61472f83b6bb03d6f3181767bb2a2bf604514cf7bc7e33bbb35e0af9b8c942a507233df50a81f5e06d28c711096bbc46b85e169195ae4ac4b3673e0b0dcff8ce0045834f8a8ada5b976a909f23a87f59d9021ceeda2140ccb4fd34dbf94add25d89f70879357e1886a63fe8de121ef8fdc94b6bf9bcca26d2a6d654548fbccbe051fe19105f93fac5842b1bfe170f71a86a53efa4
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104533);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-12319");
  script_bugtraq_id(101676);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui67191");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg52875");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171103-bgp");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS XE Software Ethernet Virtual Private Network Border Gateway Protocol Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE Software 
is affected by a vulnerability in the Border Gateway Protocol (BGP) 
over an Ethernet Virtual Private Network (EVPN) for Cisco IOS XE 
Software that could allow an unauthenticated, remote attacker to 
cause the device to reload, resulting in a denial of service (DoS) 
condition, or potentially corrupt the BGP routing table, which could 
result in network instability. Please see the included Cisco BIDs 
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171103-bgp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1a2500b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCui67191");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg52875");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCui67191 and CSCvg52875.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12319");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "2.1.0",
  "2.1.1",
  "2.1.2",
  "2.2.0",
  "2.2.1",
  "2.2.2",
  "2.2.3",
  "2.3.0",
  "2.3.0t",
  "2.3.1",
  "2.3.1t",
  "2.3.2",
  "2.4.1",
  "2.4.2",
  "2.6.2a",
  "2.7.0",
  "2.8.0",
  "3.11.0S",
  "3.11.1S",
  "3.11.2S",
  "3.11.3S",
  "3.11.4S",
  "3.12.0aS",
  "3.12.0S",
  "3.12.1S",
  "3.12.2S",
  "3.12.3S",
  "3.12.4S",
  "3.13.0aS",
  "3.13.0S",
  "3.13.1S",
  "3.13.2aS",
  "3.13.2S",
  "3.13.3S",
  "3.13.4S",
  "3.13.5aS",
  "3.13.5S",
  "3.13.6aS",
  "3.13.6S",
  "3.13.7aS",
  "3.13.7S",
  "3.13.8S",
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1cS",
  "3.15.1S",
  "3.15.2S",
  "3.15.3S",
  "3.15.4S",
  "3.16.0cS",
  "3.16.0S",
  "3.16.1aS",
  "3.16.1S",
  "3.16.2aS",
  "3.16.2bS",
  "3.16.2S",
  "3.16.3aS",
  "3.16.3S",
  "3.16.4aS",
  "3.16.4bS",
  "3.16.4dS",
  "3.16.4S",
  "3.16.5S",
  "3.16.6bS",
  "3.16.6S",
  "3.17.0S",
  "3.17.1aS",
  "3.17.1S",
  "3.17.2S",
  "3.17.3S",
  "3.17.4S",
  "3.18.0aS",
  "3.18.0S",
  "3.18.0SP",
  "3.18.1aSP",
  "3.18.1S",
  "3.18.1bSP",
  "3.18.1cSP",
  "3.18.1SP",
  "3.18.2aSP",
  "3.18.2S",
  "3.18.2SP",
  "3.18.3S",
  "3.18.3SP",
  "3.18.3aSP",
  "3.18.3vS",
  "3.18.4S",
  "3.6.0E",
  "3.6.1E",
  "3.6.2aE",
  "3.6.2E",
  "3.6.3E",
  "3.6.4E",
  "3.6.5E",
  "3.6.5aE",
  "3.6.5bE",
  "3.6.6E",
  "3.6.7bE",
  "3.6.7E",
  "3.6.8E",
  "3.7.0E",
  "3.7.1E",
  "3.7.2E",
  "3.7.3E",
  "3.7.4E",
  "3.7.5E",
  "3.8.0E",
  "3.8.0EX",
  "3.8.1E",
  "3.8.2E",
  "3.8.3E",
  "3.8.4E",
  "3.8.5aE",
  "3.8.5E",
  "3.9.0E",
  "11.3.1",
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.1.3a",
  "16.1.4",
  "16.2.1",
  "16.2.2",
  "16.2.2a",
  "16.5.1c"
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['BGP_EVPN'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCui67191 / CSCvg52875",
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list, 
  router_only:TRUE
);
