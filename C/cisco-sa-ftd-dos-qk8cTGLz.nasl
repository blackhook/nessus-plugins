#TRUSTED 991331497e1eeccc554a646b1ab90a9006a55ed4c1b52f90fc593493ef4d8642832b9a47140a6c4e1116092f2a079731a2c29798660907ada86cf451063edba61b413975016c8c64b813674bbe23b6190ae9c6ebdddf413e6e8742e3a9d3b1bc37da821aaf7ac4966fe1d5b065a3f5e192b60c515ffddc777ccb0024ec157568673d6c54af71eed452a036a95cef391dcfbebf3f23b0fa92094fa6f55124aa9fea5d8af9f1072eb80396d0c106c8667591b082a2cce357e88d37c1e1bbd5d79e13e413c41233da7a4c657e42eaeeb1d04a64d4455f1ee3e4aadc1f2218a567ef0711afe03896dfc01c3df90d727906cc0c68555e4832fcd0fa1f868c5ef54890248ff8a669bd9215f85aeb7445c7acbf179a4ac66cd1302c2ad2bfca6dd386be4fa8fd800cbe6921543c71c0b76d47574c27318977f45f56b7fdbcde341c3cc4d6fa9536ddb5e3fbf6b2ac47f71de4558054c3b0cf56eb9961d1cc246ae898ef8b75eba4e5621681c2f3e4955147d547432e8695f04d127464f3968fc655eac238848fb43b2cb4c0d37fa3a2638884e7fe6425ff7d8de524176b196019db22b5739e69b122ef226a56a4ddd83153102a927761a02fb2440fa5e6772e42301cdd8549c4ae1335b3aabcaffc35d8f4acb6fefdae45b97d66f7a6fba7686c24d62a85cd9bec280a1013016b76cba90bd474cfffbed909576217badfcd374994c020
#TRUST-RSA-SHA256 48e24d95be96f3df12c58a3930ec1f21835451a4fba6428316475d92d194cb71ac988c766cbe819e70e257042d626777ad15a4e157505d8c321f6f012a7d70d4f52bfadf3d6266ee3226fdea5914c669ded6731f944b5fc5c52832e88d9172c72c373ac86e127b9df8aa7aa44196767a288ae3e3986659df71f57293c4e8fe2a83f51604b7ba0a87e4960a8eee8d267d3de507c9fda06c81dc5884b6b416b2a007c72e5b3c1bf818e23db16564ad76b8df83d12d377603df8b385105649783ad8d56b358312d836b6bf9d130cf5c7c8d50830d1424f1638dc3d41ea8471e1f52f8483041b60da7c5783c038b20192f7588cc71c8457d24098bae1f0c3c9f34806038b9cd9822e63107a8671b53c0a2c4424e0674679ba5de6c8babc5d0f9d6b92c7260db3a8f86ecd808f9127746ee87c816d915c190d2f277ac008d39a1f48821e4f8b1a5a0314a18c3fa7680519040bcd34025ff9524b9093074e7ef7eeb4945ff1407f9143edc71c9eeb81686d7c9fb6a195737e6b656cf34a7843e79f0c74d5739da889da1bd066b8337a0e13e038ca5cc678d80596eb6c82dcf5e25ac512e8a5161e3addbd726dae4bd7925c8b4411034700f770caf298dbdd387bb2fd6fdecf9c812acb76af8cc34a0db7f400dabdfb7a72121c46a440bfaeef5fd3518aac3354b437b5d14d4dd36dae2f1f8f2da453fee66b2c2327b033b25433086c4
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138376);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3306");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq41939");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-dos-qk8cTGLz");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco FTD Software DHCP DoS (cisco-sa-asaftd-dos-qk8cTGLz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a denial-of-service (DoS) vulnerability in
the DHCP component due to incorrect processing of certain DHCP packets. An authenticated, remote attacker can exploit
this, by sending a crafted DHCP packet to the affected device, to cause the device to stop responding.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-dos-qk8cTGLz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23cb221b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq41939");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq41939.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3306");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  { 'min_ver' : '0',     'fix_ver': '6.3.0.5' },
  { 'min_ver' : '6.4.0', 'fix_ver': '6.4.0.4' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq41939',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
