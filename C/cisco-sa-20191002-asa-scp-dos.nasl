#TRUSTED 01d3fd438cd5fb234d8488299c0867539b98f97fc04dbc69dd3643cc3fb69af23017978467a86e24d82ae7752eab3985bc73bedda97168ecf8e9fa8bfb12708c6d1cb1667233e5d6d155c678bc13294d09f256d4c871704cc0c4fbc9d77a535cc8f0141d73a3ea5bacd0690e1a98c1c1ad811b8045a5bafe1bee4a9b5939a8e6a08914c23d4c0eeefaaaa362c042915aa3f619b09c587ed6a638c7020bf9aacfc51e4cfd4fbdb238a2da15b13c3ec68b9f9174a9257d73e89e81cd5a391da3654a102c9e15980529b934ac2c93de969d07936ef060c92b099b27f376296ce78e905d59c7af8df419491167eaa15ae4db32e18d608b4316fc425982296005172e531c48c4e2033917adcafac2efd756edbdce511521aaa0b49e123b855cc3c7d4ac88f174eada22d7466bbfb14d5e5135742c80a37a50967fa1d45d03e0330ed82a90ef71e05d884883f34475c3005b1c1cda057bebb03e0aefab31b0348931437b8a4709749a66c31152f0d6a4f1bb07b5a23395e4ff7e4e4a8da6a13f2039d2c1a10a1fd7102be3a26aaf3d09500c6816d9c303ade9543fc3b2c3edb7ee7b030bada8fc43e75ef476f9f782fa9dc64cc39d088e38dfdad0072efc1d15f478a4bc22efe18ff5c38d8cb9ef208a9d49bc0b90925522eadc24ec9c4988ab2dedb265408bb4a9d3bdee04364869dc210ece29f8d43d2d05de9b4d99505fa167a9a8
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130090);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_cve_id("CVE-2019-12693");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo51265");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-asa-scp-dos");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco Adaptive Security Appliance Software Secure Copy DoS (cisco-sa-20191002-asa-scp-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance (ASA) Software is affected by a denial of
service (DoS) vulnerability. This vulnerability exists in the Secure Copy (SCP) feature due to the use of an incorrect
data type for a length variable. An authenticated, remote attacker can exploit this by initiating the transfer of a
large file to an affected device via SCP, provided the attacker has valid privilege level 15 credentials on the
affected device. This would cause the length variable to roll over, causing the system to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-asa-scp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?525a95ee");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo51265");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo51265");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12693");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(704);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.6.4.30'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.50'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.22'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.2.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['show_ssh_asa'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo51265',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);
