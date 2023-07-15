#TRUSTED 1ad0371bb63d915be89e35f20d41a115abce31b1f5214ec519a0e00ea837ed888bdce0ae029de6e1a5b6e4aa6355b049d6a70de7972b68a070c351cb2a3373fc87cea9283affc83c5eed05b52f9fc092ba661dc7572c9dd48929f0cdc8627b987a52b6072ec164461cf02f2eeea76e854db0f2f7e1a5622c98d54f441340e848c89b5c43bf57d8d037d808b8bb38a2e22be6a0e9805ff49663d40cdd16984e1f0ccfbb9e9fbc95fa6cf2b605e209c88b731aa4bfe589b25afbf27a2c3ea47fee3a821350fe7e0ad797a8ce73ff2622543ac5f01c5904ce313e765b7098762f6307a3007eceb4c836baf36d8f33a96d0b30cea6635fc3be47bc1307dc466f0a31974b277cd6694fa77b57504752dab350fd3e30441589bd6193204436b76f75cfa21a5ce0ba9ca0e7b643b6c3791ee55d4506f0c46fea8324bb06645022833232bf8c15260662a7d872c2bf2905da8d46b3a02a0aa802c510b63cf8c580760e052dd5a69f808e94877f4fe77fa3e7cee3d4eba761ba4891f094457b8b1119cdd83bfec357c5ae6c140211a6acd0bc4d6eace1bc137b30b226625c4e2cab8dcc90bc478971745473ea1eca8cda322973bb85aa733091ebc581e3cfe292ecee22521559eaeacf323d7dffcc3acb7366d2cc9dd41efe617e1ed73f25a7f6a61d7771a599e56f7d3a1f7cc876b4bc15479388730a736e4f46083af1ddb4fd91597f14
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130022);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2019-12647");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm01689");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-ios-xr-dos");
  script_xref(name:"IAVA", value:"2019-A-0354-S");

  script_name(english:"Cisco IOS XR gRPC Software Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by a denial of service (DoS) vulnerability exists in Ident protocol
handler of Cisco IOS and IOS XE Software due to incorrectly handling memory 
structures, leading to a NULL pointer dereference. An unauthenticated,
remote attacker can exploit this issue, via opening a TCP connection to
specific ports and sending traffic over that connection, to cause the
affected device to reload, resulting in a denial of service (DoS)
condition. 

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-identd-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09b027b1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm01689");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm01689");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12647");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
	'3.2.11aSG',
	'3.7.0S',
	'3.7.1S',
	'3.7.2S',
	'3.7.3S',
	'3.7.4S',
	'3.7.5S',
	'3.7.6S',
	'3.7.7S',
	'3.7.8S',
	'3.7.4aS',
	'3.7.2tS',
	'3.7.0bS',
	'3.8.0S',
	'3.8.1S',
	'3.8.2S',
	'3.9.1S',
	'3.9.0S',
	'3.9.2S',
	'3.9.0aS',
	'3.3.0XO',
	'3.3.1XO',
	'3.3.2XO',
	'3.10.0S',
	'3.10.1S',
	'3.10.2S',
	'3.10.3S',
	'3.10.4S',
	'3.10.5S',
	'3.10.6S',
	'3.10.2aS',
	'3.10.2tS',
	'3.10.7S',
	'3.10.8S',
	'3.10.8aS',
	'3.10.9S',
	'3.10.10S',
	'3.11.1S',
	'3.11.2S',
	'3.11.0S',
	'3.11.3S',
	'3.11.4S',
	'3.12.0S',
	'3.12.1S',
	'3.12.2S',
	'3.12.3S',
	'3.12.0aS',
	'3.12.4S',
	'3.13.0S',
	'3.13.1S',
	'3.13.2S',
	'3.13.3S',
	'3.13.4S',
	'3.13.5S',
	'3.13.2aS',
	'3.13.0aS',
	'3.13.5aS',
	'3.13.6S',
	'3.13.7S',
	'3.13.6aS',
	'3.13.6bS',
	'3.13.7aS',
	'3.13.8S',
	'3.13.9S',
	'3.13.10S',
	'3.6.5bE',
	'3.14.0S',
	'3.14.1S',
	'3.14.2S',
	'3.14.3S',
	'3.14.4S',
	'3.15.0S',
	'3.15.1S',
	'3.15.2S',
	'3.15.1cS',
	'3.15.3S',
	'3.15.4S',
	'3.16.0S',
	'3.16.1S',
	'3.16.1aS',
	'3.16.2S',
	'3.16.0cS',
	'3.16.3S',
	'3.16.2bS',
	'3.16.4aS',
	'3.16.4bS',
	'3.16.4gS',
	'3.16.5S',
	'3.16.4cS',
	'3.16.4dS',
	'3.16.4eS',
	'3.16.6S',
	'3.16.5aS',
	'3.16.5bS',
	'3.16.7S',
	'3.16.6bS',
	'3.16.7aS',
	'3.16.7bS',
	'3.16.8S',
	'3.16.9S',
	'3.17.0S',
	'3.17.1S',
	'3.17.2S ',
	'3.17.1aS',
	'3.17.3S',
	'3.17.4S',
	'16.2.1',
	'16.2.2',
	'16.3.1',
	'16.3.2',
	'16.3.3',
	'16.3.1a',
	'16.3.4',
	'16.3.5',
	'16.3.6',
	'16.3.7',
	'16.3.8',
	'16.4.1',
	'16.4.2',
	'16.4.3',
	'16.5.1',
	'16.5.1b',
	'16.5.2',
	'16.5.3',
	'3.18.0aS',
	'3.18.1SP',
	'3.18.1aSP',
	'3.18.2aSP',
	'3.18.3SP',
	'3.18.4SP',
	'3.18.3aSP',
	'3.18.3bSP',
	'3.18.5SP',
	'3.18.6SP',
	'16.6.1',
	'16.6.2',
	'16.6.3',
	'16.6.4',
	'16.6.4s',
	'16.7.1',
	'16.7.1a',
	'16.7.1b',
	'16.7.2',
	'16.7.3',
	'16.7.4',
	'16.8.1',
	'16.8.1a',
	'16.8.1s',
	'16.8.1c',
	'16.8.1d',
	'16.8.2',
	'16.8.1e',
	'16.8.3',
	'16.9.1',
	'16.9.1a',
	'16.9.1s',
	'16.9.1c',
	'17.2.1',
	'17.3.1',
	'17.4.1',
	'17.5.1',
	'17.6.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ip_identd'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm01689',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);

