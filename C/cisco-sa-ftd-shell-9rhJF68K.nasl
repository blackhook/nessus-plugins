#TRUSTED 39a867e4bea5dd6b0030cb733794fb41025c7567f3316a25556b4bd7571f25d54cd6fb96f94c36efc42ba38c6c17e1d7baa4bf54315cc69510aba29c3ba46f64f398bb646381fc3d1f932873124e88874bcff5d2a141f9e78e97efca1095fbec3fb02b57143e526c4c6a6737a02ab88f95e572c4c7932633aabb62e753515bdd5e299992b8b0e2750e0caebec6ae2942f16b38b9b620ac775447c44577d1c170553575c80c4e98b42fe8ac384b84a79a12a5d605e1cd1bb6f2302fb65817b1581bb872b3c6085f6e466bad01ee48f69eb48d2f3c9c247c46283ac1fe4755f085daf532f9269145da7d4b8090941453efbc62fdda0a0c5c3bcf78a1abe3c466e1da41faba7346d0fa2858670e785460a4410fab92198345ad05fc807895e1679dcddbf7eca93e6008018399695357271ba934d8a006f05ad6fa6af80f43d21f85f7bf8f9fdd6da41a2c6a0ab84ad1f3ea745d74b316f91b67640a0b34a8afa49fafaeecdc9fbf70a2e17ee85def4f0cd0aa78dde7cd32f47dbe310a3f4240395add58981df7910a9bd8e12bc46fb17725040d311afcd64026b78ed4b193f00f801668c23231bbc521ee13931905ef17c820e28f5c33cb828ee919b8755d0fe4955e75691053b53ea9c3091d3c8a64daf3536450269e1c18ddcaecd77dd22d4ddc0591e3238b4aab153444472a3abf311f659056341467a1ae2dbc4f4c851200f1
#TRUST-RSA-SHA256 310357b657c8c59afdd8c6b10917c4afa7872ef30127d461dba6c604043c1b8eb258625ddddd35f799ae206f9a3a70b14cf2b1d9532e07c50889023727ba1669e81460d55d0c3133b4b2cb94049acaa13241168c9215e20228b9d90af3e93a91d26c6d99cb2ea696e4b5700bf8a4fe720f9058f0bbce8e6dcde882c0d84a273c92d3acc4fe132df0ba34f72bc8cd40e8a65322a77b9f5e966f60bdd83c99f8d926e7312e4cf1240ba07ff10a6d29d4365a8398a0f16301cf77c5e1f067c5e23a3aaf4661e9bafc4c4eb25cdf0c1908b399c35f28f363cc80f6dea556efdc02a4af8373c67690f52ba35a196d7be41942143622ec100cdeb862ac6d786becdad9da4559c8e5de417a5706ef02ea8bb7ef6f50f3049c1067b8b6350fef92f62186bcd5a4432ec249b6b98e5a1996852f7afadca6fc7b19016218c13992b67edae02072f50ad83097e145969e0560c35472a797f5ade3364aa8dd3e2cb2ab5bd03e69b6d2d5cf340167739e81e7264d43dfc6c7f0828230fe3d22695f444b32c3ca3c2da93fc470964578ff88a27c22e58e1fa4ca33f369cead395294d0074c826c7c1bd85d8db7aafc5bb8edf5b4cc4fd5d20224146031664d3ae1b8ae1a819af4ad712c189943db7eabeca7d978332b8009c4ae4715e2d9f2782685e588d4fd28dc370e4abd2d62bb5f3d2d61c45b84e1742065510e858b9b61b5bcbb291e8c2d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136669);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3253");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp16933");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-shell-9rhJF68K");
  script_xref(name:"IAVA", value:"2020-A-0206-S");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Firepower Threat Defense Software Shell Access (cisco-sa-ftd-shell-9rhJF68K)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a shell access
vulnerability in the support tunnel feature due to improper configuration of that feature. An authenticated, local
attacker can exploit this, by enabling the support tunnel, setting a key, and deriving the tunnel password, to allow the
attacker to run any system command with root access.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-shell-9rhJF68K
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?979c9bac");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp16933");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp16933");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3253");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '6.5.0'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp16933',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
