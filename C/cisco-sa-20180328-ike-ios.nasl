#TRUSTED 5bd221b9e8d19c67760171f9d0b4aa6ff3e19b88aa89c74f6b7a6be1e24f662a3e020939539e83590366bdf1be641cd6421f7c4a6797d56def3edf80140ba994f2c2deff6720431bd9ea43cd33e1608b278899a1f6ebba69b39340aba7743d082f73cd08614d1d92cc1ce415de0f8c070372c1d7aab57d8ddcad8c2ff5931c4e28e6d7054b56401f9d78c6de3f7c8b97a1d89caeac74c8a99750931dbae38e8ec6e460551d37fdb8594307179229f3940e1c66a08267067dbc2e8c1347adb9c6725a93dd6462e533ca6c0b854f34a4ce44c609dadc643913cbe527948e1a1d8b06bc6c17c7cb512fa90b6a0a3c565b690d73ee5a346014fe215e433b4e3407787f40953f795659b76d2d279c4bb9d054b2e3330fd68fae21bb878e0701d12c192ae761b84079225f01865f23974f2da235d8c009ddedc922d845110b5677460f8fb9c1e284767ed2300cbe448dbee9a6d3335e7922835aac027f3edf5626b5207807997c2b402b3b19770444a6908bcc2c726370149419b1c840da1cf39f66d465882582614bd039d1f630b9728aae69c7903b485e9511ef5cfa4a8ca8ea89d0d47b8fdac64d0f79124db2f530d948929f6a5970504824125db579c9d6861e5c5419fd3a572b0d40acdac888e487f722e2dbe905576968a13d1431b14b00fcf1607d807b4e05149f55de3299525993ed04fc81665a83aa563a6384e4366abd52
#TRUST-RSA-SHA256 4bde2885c4e2f4f8a2c942f3c7c050f7f0027d00de87f1568fb7355993b8076e50959da0e00ba780a4e1ecd3993ce209d2afda598c3dde3df51883d9419641fac6b4567cf9bcc335901f3f37c3cae8a50e72dba6a1b69609a2b1666903ac78ff353b923cfe7dc1641b92d4cba188ef94e774ab7a193ae658f615add3760480093a9d2081f438d910e382a51dcbffb36b53919eb9fb8e557c2393c5e4763093d0e232affc3a9ee0d38500fb10edf22644c2d963dbaa9aa97c9c39f13a61df6d040d926ccdec56357cc21297e8fc003e22c67d7ad427fd2a0915fb59e7d7cd40b4c167ad6ff3a92f2009abbdfe381d05df16a830c23fd4e56f331299db317736618a66505e6eb02329f6520f2a0d388692f2fb7bb3dfc274e6aebde75b943ce9a0ff5c41adf2ce92dc7f91312fd866de15439d607e0f19881e4abf6bdb381c62e25285107f4df4f46a845bd7fd377b639d5d2dcfb29818c4ea0c6939ad4b2474cd9341440d455fe15c9953eb598bfd5ba0edc35923be6e25c0b5f1e434e77661ccb7f295ac164f9c13fa663b228672a571d1b33ae42c2375faa0ad6010bc48cdacf79614583089e3d98332332735d42dcedaffa6eeebfae7401358387872e2bb0910f0d9b37288eec1e27ec4c6064e86730f9d68cb60903a83cb5704cf99094245732750bd37e2e49ed62b6f03af0e87421a30df76a070bd5f8782b7844db00d63
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131325);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0158");
  script_bugtraq_id(103566);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf22394");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-ike");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS Software Internet Key Exchange Memory Leak (cisco-sa-20180328-ike)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a denial of service (DoS) vulnerability in the
Internet Key Exchange Version 2 (IKEv2) module due to incorrect processing of certain IKEv2 packets. An
unauthenticated, remote attacker can exploit this, by sending crafted IKEv2 packets to an affected device, in order to
cause a memory leak or a reload of an affected device, leading to a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c962b883");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf22394");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvf22394.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0158");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
  '15.2(4)E',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(4m)E1',
  '15.2(5)E',
  '15.2(4)E3',
  '15.2(5a)E',
  '15.2(5)E1',
  '15.2(5b)E',
  '15.2(4m)E3',
  '15.2(5c)E',
  '15.2(4n)E2',
  '15.2(4o)E2',
  '15.2(5a)E1',
  '15.2(4)E4',
  '15.2(5)E2',
  '15.2(4p)E1',
  '15.2(6)E',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(4m)E2',
  '15.2(4o)E3',
  '15.2(4q)E1',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(4s)E1',
  '15.2(4s)E2',
  '15.5(3)S',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(3)S2',
  '15.5(3)S0a',
  '15.5(3)S3',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.2(4)EA',
  '15.2(4)EA1',
  '15.2(4)EA3',
  '15.2(5)EA',
  '15.2(4)EA4',
  '15.2(4)EA5',
  '15.5(3)M',
  '15.5(3)M1',
  '15.5(3)M0a',
  '15.5(3)M2',
  '15.5(3)M2a',
  '15.5(3)M3',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)M5',
  '15.5(3)M4b',
  '15.5(3)M4c',
  '15.5(3)M5a',
  '15.5(3)SN0a',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(2)S2',
  '15.6(1)S3',
  '15.6(2)S3',
  '15.6(1)S4',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T0a',
  '15.6(2)T2',
  '15.6(1)T3',
  '15.3(1)SY',
  '15.3(0)SY',
  '15.3(1)SY1',
  '15.3(1)SY2',
  '15.6(2)SP',
  '15.6(2)SP1',
  '15.6(2)SP2',
  '15.6(2)SP3b',
  '15.6(1)SN',
  '15.6(1)SN1',
  '15.6(2)SN',
  '15.6(1)SN2',
  '15.6(1)SN3',
  '15.6(3)SN',
  '15.6(4)SN',
  '15.6(5)SN',
  '15.6(6)SN',
  '15.6(7)SN',
  '15.6(7)SN1',
  '15.6(3)M',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.2(4)EC1',
  '15.2(4)EC2',
  '15.4(1)SY',
  '15.4(1)SY1',
  '15.4(1)SY2',
  '15.5(1)SY'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_udp_ike'],CISCO_WORKAROUNDS['show_ip_sock_ike']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvf22394',
  'cmds'     , make_list('show udp', 'show ip sockets')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
