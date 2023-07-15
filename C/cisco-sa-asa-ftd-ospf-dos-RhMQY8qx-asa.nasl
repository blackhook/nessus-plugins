#TRUSTED 91a8619242cd4ad78b71ddfb31bb12d7ee74cdcc67a25950e577faff4332389689e10533fe00742f3562ce0dfd6de0b81850f685d927e299125f086dd405ae1e59624fa2022270186edde65cdc70f07cf757df8c8c60129afda0f6b212ee4d9daf713d3bb608cebfa37c028912070a6f579fef172fb8c31a3c4e03c185f2fc0cedb930269735d09342ec69a80d630209e9d2f621bbb43dd8ae8e34d8097ecec1f9de43d1c21fa9384b732bb8ec6552ecbbae3da2a7be5cfe358fd44e4033d58a335db31d9cb08602ce7384f9544aac3764e2f9a571e2a746b7564bd99a0bd3809aa1ce1b5f7836fd6e82deba86b2c24b553ebe403a51bae89a1eb6638544afac066eae837a0c79673d82a0e2e0cfec20d2017299668355e1ce86484b20a0ec7ab650df200c2ba7233ab87484157a18d57895c8c776bd63a202adfdbf297006c2bb909fa32a8488b3056e547b0be20ac5e789520304c7ce2d628978db36b8bc83017431df13c21a1e0ba21814369af7901f8fa93840d1b2ac48e621538311884bba31cbda41fef61999fd66fb57cc1808c1433754e048939197b834a3cd13f1282f6255ef95fb6c6ae38d02b3de59dd8473e2e998c255dadb6cc053422b9808184d2ad4a6e0a6e6324363b6d8a73e75baccaa5e45e529bb562371bce6d870ff8b0b5c942acbbe695db18dbc37abf124373387296c700bd7e5c9e3e42156aad073
#TRUST-RSA-SHA256 b1c64b1be366d0a5083e5543d9e5278992c19bf868f6bc8fd780ebcee55977b4afbc6ada9d0b6fd637cb418766e034762d34cb520ff0c54ac51a0f839723880b210ac5ad95e167ef4d6c393dfc38b4ba3d7f672baf700b483878b3566763fec8a38ab06cde42cd46f2930e4b65d1d911395c43409f6c041d613361c65bf703786ee7f75cc19d2300d7bf4cbaf06344da9143d183324e0ba3e17bc5af9670e1afe539995917c58b010a5d5c8f51de71b3f0fffb4789f0bfc080c3b9132e33d83303dca0aa19c5694f9ef8f8f080d33c5bec4ab2335300679abb11539f85a757fd6a0805dc440af20e1b7c588414bf5a2df49204699be74e4eb96753ca8a28ba567f27d817eee78cb9cb8749d24a8731196684b2ede1e3987d9d2b8df5ed9bcbea0a9e684024fa9fd91619e6dc174809eadf48030b5d7cf885866dbca741666eecf02ef1ae821f98790fcb36abb848a49f15dd516433b8336c214957d0fcbe20759af4e9d6dc88142f3ea92726ec3878a35c50b424db492cf01f162f9e36b71561a95e0dc6d7d112d87284fdafdf505a0677a391db5e45c6a5bf1d1157bbd699b62322b9952f9ce284d222031afb941ddbe55112c7553a85749d528b2fb6c1547ffd6213b4f3f1543bd971eef3f6ed7ddb8107d63a13e89133d0ea09c49aa0e98c7d565b1a47fc8a244c97bdb5540ba5a6a937d017ee433393080baad684b223fe
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138892);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3298");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50459");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-ospf-dos-RhMQY8qx");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco ASA DoS (cisco-sa-asa-ftd-ospf-dos-RhMQY8qx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability 
in the Open Shortest Path First (OSPF) implementation. An unauthenticated, remote attacker 
can exploit this by sending malformed packets to cause the device to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-ospf-dos-RhMQY8qx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de2dc268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs50459");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs50459.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3298");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '9.6',  'fix_ver' : '9.6.4.40'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4.17'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.66'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.37'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.3.7'},
  {'min_ver' : '9.13',  'fix_ver' : '9.13.1.7'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['asa_ospf'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs50459'
);


cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
