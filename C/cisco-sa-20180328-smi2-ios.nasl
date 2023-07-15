#TRUSTED 8776fc3cadbbde7114ce8efff63519b37acf83b1de0cf430603931252519cbda9649be31f2ce4fe8d58728d38de314dbe7652d1abcf8216a689725e599ae643ee05e6cd5ddd96d67ca5a173c7cd338f484f8fb99080de3db12207922b11f722fb9128e283d709d1026810f9a4835c1ad69fced4cf94a041a659200d6bd094b2fab1be0ae2fa635b0418ce9b07b10696382b9d006efb27a27a141ff6266f28f0b3b19740bd5df76a98ded1d559bcc5ad987d12840c145709e8bea2bb2cb3732c4f75beb1bf3d64636e1df489b6f208ee2b326bea8cdadb88b493b1bba5f7d2c7d457bc50f504f4fbe1aae5c5f2c403d0031208d8f0cdcecaaa66815470efb8ce2364065a76c1ad25ca53b92199209f134faf276059a1be4cf046cd803a6a9fdc68b14c48f7a9d995ae74a70edc58a65bce02edd55dbfbe39fa72bd880f885212c5c748943f091fa5c9b3f615ba81a83379733c612a0fc704417fc38b857b9a8c7a89a2e93e3be9498fe118e532166a8f21e9b680a05b57b98cf49adef8152272bf2a52362c561e5523d1ec37b20a7c2e06d96dd575ddfbf0a8a010226f6129f5638ff3b491efcbc9d4cb574fcf511d03d34003b711f1ce9c0675435e4f6326279bbd8117ffcc4fe48b8b1aaa904ffaa791bf355ed96715f52c88e8fde2eb3205427953de5a740eea864134c485051dcc62ddce9ba93abe2cf49703d9169898af9
#TRUST-RSA-SHA256 708e5ae0a9ce46a9723c08167493610de808cb78aad460cc3255f832249e1a8e512d85c324b29f660183d73657cc83f5a60a0dd17e36368fcb7054430673fa0da8346df54550f2af9e1fb1326ad3f56cb6bcae04e0c69c387b4e0c97a6bfea867668d058d2a01578284a0574a51577e21b1bbee513bbfcd64338970fe85e36a38955153227035dd122fb6419157200ac13fdc6c67e40f0288fff8ecbeb6bbb8a538b689bb04fecc6e26def7740c4959b7276d5461c6c1c4189dd6cbc2b52e83ed8231594b9aaa436dd4abcc149223e9634f6790a22478350cc3eabcab65b9c619c79ad4bdf6ee526d139b1ba4bf5482cadb6099feef2763ee456794855b0df942847d79d0da7dc76d65e185cb6242f4ea67809d872b299078732cf23e6805d84e559753acd2be8d87d4355c9e9d188ad7bdfcf5f0d4dade037dd0952a1f4dfa7e165fa61942fe55636a296beff04b51ed2eb632676aaf87badf85be04a6b62dd9900112c54fe77dbc47cad3f3bb3ee04bfbee3e3b1bef238ccede2a932f80020d3b49a4deb1445ef1cf505de8672deac5bc6af2ac53a77c963199c0dbf6d84e041db9a66e7ac79b8e5e542c4a2f3e9861b24500fc400df49e3addf4fcd0473e38e7a5acf34b938bb680a8c4d029a5f254a688114346ab0fffed894a7a03efcb95bd75d10ae3efa542424ec0808ef093a430e1bccc366432e27fcbaffda8c519a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108722);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0171");
  script_bugtraq_id(103538);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg76186");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-smi2");
  script_xref(name:"IAVA", value:"2018-A-0097-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Cisco IOS Software Smart Install Remote Code Execution Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09597efb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg76186");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvg76186.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0171");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS");

version_list = make_list(
  "12.2(55)SE",
  "12.2(55)SE3",
  "12.2(55)SE2",
  "12.2(58)SE",
  "12.2(55)SE1",
  "12.2(58)SE1",
  "12.2(55)SE4",
  "12.2(58)SE2",
  "12.2(55)SE5",
  "12.2(55)SE6",
  "12.2(55)SE7",
  "12.2(55)SE8",
  "12.2(55)SE9",
  "12.2(55)SE10",
  "12.2(55)SE11",
  "12.2(55)SE12",
  "12.2(55)EX",
  "12.2(55)EX1",
  "12.2(55)EX2",
  "12.2(55)EX3",
  "12.2(55)EY",
  "12.2(55)EZ",
  "15.0(1)EY",
  "15.0(1)EY2",
  "15.0(1)SE",
  "15.0(2)SE",
  "15.0(1)SE1",
  "15.0(1)SE2",
  "15.0(1)SE3",
  "15.0(2)SE1",
  "15.0(2)SE2",
  "15.0(2)SE3",
  "15.0(2)SE4",
  "15.0(2)SE5",
  "15.0(2)SE6",
  "15.0(2)SE7",
  "15.0(2)SE8",
  "15.0(2)SE9",
  "15.0(2a)SE9",
  "15.0(2)SE10",
  "15.0(2)SE11",
  "15.0(2)SE10a",
  "15.1(2)SG",
  "15.1(2)SG1",
  "15.1(2)SG2",
  "15.1(2)SG3",
  "15.1(2)SG4",
  "15.1(2)SG5",
  "15.1(2)SG6",
  "15.1(2)SG7",
  "15.1(2)SG8",
  "15.1(2)SG8a",
  "15.0(2)EX",
  "15.0(2)EX1",
  "15.0(2)EX2",
  "15.0(2)EX3",
  "15.0(2)EX4",
  "15.0(2)EX5",
  "15.0(2)EX6",
  "15.0(2)EX7",
  "15.0(2)EX8",
  "15.0(2a)EX5",
  "15.0(2)EX10",
  "15.0(2)EX11",
  "15.0(2)EX13",
  "15.0(2)EX12",
  "15.2(1)E",
  "15.2(2)E",
  "15.2(1)E1",
  "15.2(3)E",
  "15.2(1)E2",
  "15.2(1)E3",
  "15.2(2)E1",
  "15.2(2b)E",
  "15.2(4)E",
  "15.2(3)E1",
  "15.2(2)E2",
  "15.2(2a)E1",
  "15.2(2)E3",
  "15.2(2a)E2",
  "15.2(3)E2",
  "15.2(3a)E",
  "15.2(3)E3",
  "15.2(3m)E2",
  "15.2(4)E1",
  "15.2(2)E4",
  "15.2(2)E5",
  "15.2(4)E2",
  "15.2(4m)E1",
  "15.2(3)E4",
  "15.2(5)E",
  "15.2(3m)E7",
  "15.2(4)E3",
  "15.2(2)E6",
  "15.2(5a)E",
  "15.2(5)E1",
  "15.2(5b)E",
  "15.2(4m)E3",
  "15.2(3m)E8",
  "15.2(2)E5a",
  "15.2(5c)E",
  "15.2(3)E5",
  "15.2(2)E5b",
  "15.2(4n)E2",
  "15.2(4o)E2",
  "15.2(5a)E1",
  "15.2(4)E4",
  "15.2(2)E7",
  "15.2(5)E2",
  "15.2(4p)E1",
  "15.2(6)E",
  "15.2(5)E2b",
  "15.2(4)E5",
  "15.2(5)E2c",
  "15.2(4m)E2",
  "15.2(4o)E3",
  "15.2(4q)E1",
  "15.2(6)E0a",
  "15.2(2)E7b",
  "15.2(4)E5a",
  "15.2(6)E0c",
  "15.2(4s)E1",
  "15.2(4s)E2",
  "15.2(4)JN1",
  "15.0(2)EZ",
  "15.2(1)EY",
  "15.0(2)EJ",
  "15.0(2)EJ1",
  "15.2(5)EX",
  "15.2(4)JAZ1",
  "15.2(2)EB",
  "15.2(2)EB1",
  "15.2(2)EB2",
  "15.2(2)EA",
  "15.2(2)EA1",
  "15.2(2)EA2",
  "15.2(3)EA",
  "15.2(4)EA",
  "15.2(4)EA1",
  "15.2(2)EA3",
  "15.2(4)EA3",
  "15.2(5)EA",
  "15.2(4)EA4",
  "15.2(4)EA2",
  "15.2(4)EA5",
  "15.2(4)EA6",
  "15.2(4)EC1",
  "15.2(4)EC2"
  );

workarounds = make_list(CISCO_WORKAROUNDS['smart_install_check']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvg76186",
  'cmds'     , make_list("show vstack config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
