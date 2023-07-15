#TRUSTED 3b4acd46c762036ea1e9894337576689ded2c16fc50ef8d0078baf6c51a975418ae561e352efb7b33038e6ed2998250453a1a3ec6f7b43d791a075cb25846517febe9062ff1655f5b9e1a78534d400f9cf9cd8c13afde0e32fcc0c7ac21d61d19d92b6ac1b089882afe272803329125fc190625a735be93cfcd832d05fdeb349f9ae5cb4f3c7c02a49fa12c8bc29284ca7936612161f79a8b0f2f1e469bdabfd860e726e239faa646c5c19b50f0ada4f3296ede32fce58253faab9eb573386386005e25feb8b7f5949d295503fb46a26f6880cd91144d85a4c25c2cb019dd5044aa7a221cdf5643845b6439504fa28f232f08f39ea4269389c0c249fbbe101ed7593cb082a2975d41ac3aec64a70ba7529a49a0c4734a4e15a0e7b1612c608caba3160d87ed3cb9eea5b65f42f14f10b3634803124ceb688c1d126dfd13fe815df580b237a0855bc588ae6f3c19363b685fd82861c88d1b7a077c5f449bea2763e248be515abd78cb225c31c8e439a4127c05a1b24943936364dc23be9580973fbba9aaa6bd12ba2d611b7c2df4502255dcd443147a0d9df6b408ade25996fc94e9722c51674e9e679c6a2e042ca34444d74d68c1ad200fa4a72d22f78efe36ae27e5dad4aa4943b03295f74f730da116c9179125b38e65066ab8a6a43d645758aa6a6d0f795c4990d3666247fc89d8372ab5ca2f296bde6eb04d7ffc972ffd4
#TRUST-RSA-SHA256 7aae50b41de0b4ad6d97b1e4768705b8bbc7febd81019b7df5e95055dcc2b37bff8e5c677191d2a3ff3c120da6a963018bcd5fe0616b2c278d7b3dcf54251f2952eeb126414b03274de487d3a4fa8afeb3a628bfe434b61cb72b5164dacc8f9e82f234a0b2b34a7dcfdf1770f00ade04814f99629cd4faf93da7ce11c4f80b01ff5447c52024b16063a6600132b5171ef161e5cc5f056f9e7c9b6954b6675ce20ac39685498fe5e80cda9b78a0c873f029f725e150a4f4767ddf0c25e37a473bc229106f456b658f41428a0f2963ed217b09503e7abb191cc966a729b3ade9fe01532475f7b3a62ca9c417f3a8ad174a8526762ba5849f5aee018f40388dfd164a2b94788a805b7e8e20fabb22cd43f1d9ed5b2839fc43aeedd0a2d705ba201d049d97bf5d26e7df121fb624918ec8f078624d688be0cdc9628d0486788c319d838f589d8b77bb66a8d6c92cb0ab2310df042271a9c415c99f9a81377dcd39512efdf31841075085dbe821dc8d7db7c8ea5495fe68a59df368586b3e7d62ef0e26a312f3e2de054bc98bd9637eaafaad8c11b98fc44c71b3872ed960988d57c3d9f4f5c6c522036174c25408db22bc8f8e91504b869d00ee7da125937817874a129a5f466a868355cd58445568d7d79b1f22831222deaef0da184896eaa350113f04d5340c7b1430b01390e94d1433e9fde3d971da958c30ec2dc5decd381af7
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169453);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/03");

  script_cve_id("CVE-2021-1624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx37176");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ratenat-pYVLA7wM");
  script_xref(name:"IAVA", value:"2021-A-0441");

  script_name(english:"Cisco IOS XE Software Rate Limiting Network Address Translation DoS (cisco-sa-ratenat-pYVLA7wM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Rate Limiting Network Address Translation (NAT) feature of Cisco IOS XE Software
  could allow an unauthenticated, remote attacker to cause high CPU utilization in the Cisco QuantumFlow
  Processor of an affected device, resulting in a denial of service (DoS) condition. This vulnerability is due
  to mishandling of the rate limiting feature within the QuantumFlow Processor. An attacker could exploit this
  vulnerability by sending large amounts of traffic that would be subject to NAT and rate limiting through an
  affected device. A successful exploit could allow the attacker to cause the QuantumFlow Processor
  utilization to reach 100 percent on the affected device, resulting in a DoS condition. (CVE-2021-1624)

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ratenat-pYVLA7wM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82b10ce9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx37176");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx37176");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl", "cisco_iosxe_check_vuln_cmds.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '3.7.0S',
  '3.7.0bS',
  '3.7.0xaS',
  '3.7.0xbS',
  '3.7.1S',
  '3.7.1aS',
  '3.7.2S',
  '3.7.2tS',
  '3.7.3S',
  '3.7.4S',
  '3.7.4aS',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.0aS',
  '3.9.0xaS',
  '3.9.1S',
  '3.9.1aS',
  '3.9.2S',
  '3.10.0S',
  '3.10.1S',
  '3.10.1xbS',
  '3.10.1xcS',
  '3.10.2S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.11.6E',
  '3.12.0S',
  '3.12.0aS',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.0aS',
  '3.13.1S',
  '3.13.2S',
  '3.13.2aS',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7S',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1cS',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.0aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.2bS',
  '3.16.3S',
  '3.16.3aS',
  '3.16.4S',
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
  '3.18.0SP',
  '3.18.0S',
  '3.18.0aS',
  '3.18.1SP',
  '3.18.1S',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.1gSP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.2aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.18.8aSP',
  '3.18.9SP',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1a',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5b',
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
  '16.5.1a',
  '16.5.1b',
  '16.5.1',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4a',
  '16.6.4s',
  '16.6.4',
  '16.6.5a',
  '16.6.5b',
  '16.6.5',
  '16.6.6',
  '16.6.7a',
  '16.6.7',
  '16.6.8',
  '16.6.9',
  '16.7.1a',
  '16.7.1b',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.1',
  '16.8.2',
  '16.8.3',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.1',
  '16.9.2a',
  '16.9.2s',
  '16.9.2',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.3',
  '16.9.4c',
  '16.9.4',
  '16.9.5f',
  '16.9.5',
  '16.9.6',
  '16.9.7',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.1',
  '16.10.2',
  '16.10.3',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.1',
  '16.11.2',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z1',
  '16.12.1z2',
  '16.12.1z',
  '16.12.1',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.2',
  '16.12.3a',
  '16.12.3s',
  '16.12.3',
  '16.12.4a',
  '16.12.4',
  '16.12.5a',
  '16.12.5b',
  '16.12.5',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.1',
  '17.1.2',
  '17.1.3',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.1',
  '17.2.2',
  '17.2.3',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.1',
  '17.3.2a',
  '17.3.2',
  '17.3.3a',
  '17.3.3',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.1',
  '17.5.1a',
  '17.5.1b',
  '17.5.1'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['iosxe_max-entries_patched'];

var reporting = make_array(
  'port'      , product_info['port'],
  'severity'  , SECURITY_WARNING,
  'bug_id'    , 'CSCvx37176',
  'version'   , product_info['version'],
  'cmds'      , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
