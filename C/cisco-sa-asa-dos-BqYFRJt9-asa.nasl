#TRUSTED 9a1cb8c306947b0b770315e1690bd50b5199f90c5568be8c0fad718999df034e0443e8e4e9edbecf8395913158cbb0e277580f6c13b5d7b9cb922fbf4e78a443d6837006b1bfae5c3148001df516da267063172800c0a1bb5832d06135133bb96a4161974d48f4ea69a5c1ae590a22628ca1b5e3b4e4420cb22fc5499fa7c9e0099e5e79b3fad2244911760ca881fe1422ad3d0acf9e065416e0ab7d2562624dabb58e78b08f7e26727948efdfa6b71f684b25b90d8fc86ab56f9705867b9f1f1797024511c5ed2f9cbcb90e994f09c49a2fd1f11a5b71c533f0e2ff620d5d26f18ec3a476739164e2f1c263ce62564f643ff84dd551164339527226290b428f09237d76e1f166b26727062a3a4f55019468d61e609e1b9764c5544fde107313c978818f296aa9adce2abaff34933e9638034857d90bf73d70b3a63724950804847e0c00ec04586d44bb67f5dbd79405cae3066c6c300c0186e08704284eb795265e307f73381e051038256256ae5ea1ebcbf6251cf2b1c5c610102d509050dca1693a3210333f6e499a3e5b7116cf6140a34cb55e0aac6aee38b025bfad2a98d6d9095ec0199fb33af7e41051ce2a18d407edb3200c35b3b74108ae68a8c3c0d4399e91ddc585565c4a0c3111862a4352d7293b5dac67e327b73e75524b18ec5bc3dfde87665f160bb675d6123c89a2ec4dc3bf821555df59e7699ed032838b
#TRUST-RSA-SHA256 4b0cbeb37eec56a8ce08f7634f60ec097a46048447c9760a0e419d8a3176bace0246a9e2f9144114595ce17cc69ae339293ba1609a329fb5857579754cfd18570682d271721644dbc58b12fda03c31908394b02eda70055853bbcc190dff1002d54a5854fef50784352bd32ffb849a14437dc874e8bc32b068970f3262d4e1ea18fc8c47462635347cc73eb610a2ed81a6991c8b72974f3f23d609519c2ab8625f49d88afd0fdcf11cc8ebab7dfab90c07caae3d2b1c20fd270ba6cfc3b46b52cbd8379d2e95da65a26b8c65919fa93e7abeb3bad1be7d80ad229726c7cd25ad9d6d551adae88a2e622cec5e7273b60820602ace4d523fa1373b444260db18476439748863a1aa7762622d0b93b9cb1c3ce629758fc4541339725561406b279a1b203b1dbd0b6931218ea5dc66002ba54fe09f364ac6add37443363737e0520df89d52898d4d89cc919f40197729706b1c49a8aa435e58ad6574935f0d4e7581af2ecbb22596cec1e0482a18e2aaba30c217d9cd2533e434ab4d231b2bfead381f8bcf993f5ae5c0f77810ce154b0ad8c8f1ae89f9f066fb7545766e511a126b5d567721548b68581aeeb3393e7da0f94434c511730c55032c998c159fec7b4e6c015c372e4b38419ffe686418ba0f146d9c3d5df2d8ace26da1a0f29fff6ee9d3302113fe7ed04ac13ad840e9c8546d3eaed01a9bac08487288680e55231fd7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136588);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3303");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq66080");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-dos-BqYFRJt9");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Adaptive Security Appliance Software IKEv1 DoS (cisco-sa-asa-dos-BqYFRJt9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the Internet Key Exchange version 1 (IKEv1) feature of Cisco Adaptive Security Appliance
(ASA) Software due to improper management of system memory. An unauthenticated, remote attacker can exploit this, by
sending malicious IKEv1 traffic to an affected device, in order to cause a denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-dos-BqYFRJt9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24d5d1c3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq66080");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '9.6.4.36'},
  {'min_ver' : '9.7',  'fix_ver': '9.8.4.10'},
  {'min_ver' : '9.9',  'fix_ver': '9.10.1.30'},
  {'min_ver' : '9.11',  'fix_ver': '9.12.2.9'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq66080',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
