#TRUSTED 5eea3e5fc93ed9e3cc300726d12aad4cc2f349c22bfe4a79d3546dbca8a3d2d0f6bd2863b8fd74edb05231efd44a902403cea47c43626cada58a746de61aac703960cb7e0bdd99ae850b82fa3bb59b46fdd3d4e0fb528446383b1181a4ea1a3ccd014aac4bd96d201cbce2782cf9782200ddaca9727303fbcc66ee4dc63995d3d21138e91e9ebb5ada13a4a9d9489ef262338bb4d5797defb36962dac7f6e5f0f398fedd2e3fe789c1e1b87618205218f9623ebbd06b19cff24efa7c36f4338b82c4b0cf04ccb7169656e8660b8f5a639096d403582b7de68ce9873a7e5cf76f3037df3b896e04c3546af73e9642a10e53ca5fad5d598bc66d7fce0b36a7dd4da5d97451b5e1971c9138395b779cfa9f0371e7064a09011f70d23111e1cfcf9d6876d468ab2717c4a827b2a12eaeb0fbb309f53df9c5523976399316eb60863977de3c44092511ad5ef39146a8fbc1a91ab724f465850a4cdff584dea8025809a444aba4e4420a0f718f2c963064eb6222584ff1f301d68093b934f5598cdaccca03aa9048868aac3148a68b7cc4398e86983c8de74626d3ad703581185c3f638c49d645e33ace6adccb9dd0e382c023bfd13ae2a92c5c8c73f3b8f83e7e01a79e405b41ee6874f301792f499e7ea874d6aa601e0b965a4e77c243b45c29794a7ba3b814dac53682e5caea9f97e61712ba3ee215989837db587c69e4f746b6ce
#TRUST-RSA-SHA256 4b507b07936fe176a2bbf715f6a382ad79580cd208e750924bc5142af936cccf37d3e4c2d309489f875be1dfb9028c3841b64ab3c49399e0ec60f2b567032221d2da17334b7fa7c8725c20a3d324c76ff82a0f82ead48c072ba459e5d3e6c358971335c4fe615ebc73554bb701f503e5407beb696a1f45ec121126a91cc76f44aa7c56b6ab1d4c715e04084cde19d37ff05cd9f67f9cb3f2c5c7cba6e228464911423dad495d5010f035a42320c82af363c0767897d1fea952f828a460ee66884a09f252e7bb89f0dc0c9571cae673a356edd55ce985780887677b2c07c40e74dd2d60db56d04995a5fa372ca6e48bf36ab683da2cb450ec824f49a755b86f0d23141af7917fdd2048ddda39a3c2801d5bbfc680e6b3e70a150f7585592d462d5b3512401dcadb40ec2ce4562091d03bd1cae71f9aafdd195a51034a7fc569645d5d83770223b797119a97a025f8e1c32ce0ed96a1966a170a2c62ce971cbf0a545fce76957d2b6569096a35ce30e390737d642e5af65c67902c8cc2056a83aac8fb98ca31ae2337dbf96f57ee4e2770392f2e28de3d8b40ec662fc6e841836b25b9d8b40cec0c18aefccb8f8ec79f71890088487fd7e99a1525ddbbc007e63dada534cf5a98d0e86936ba0937ab2af94598280230caa1e79325478058e7b1f742f6a9cbe6904476e8d401c55cdf8b1cc90cada0faeaa8c1d9e0fc3b2a1c004d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150996);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-3580",
    "CVE-2020-3581",
    "CVE-2020-3582",
    "CVE-2020-3583"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu44910");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu75581");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu83309");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv13835");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53796");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-xss-multiple-FCB3vPZe");
  script_xref(name:"IAVA", value:"2020-A-0488-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2021-0031");

  script_name(english:"Cisco Adaptive Security Appliance Software Multiple Vulnerabilities (cisco-sa-asaftd-xss-multiple-FCB3vPZe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-asaftd-xss-multiple-FCB3vPZe)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by multiple vulnerabilities.
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-xss-multiple-FCB3vPZe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f256d96");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu44910");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu75581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu83309");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv13835");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53796");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu44910, CSCvu75581, CSCvu83309, CSCvv13835, CSCvw53796");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3583");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info, vuln_ranges, workarounds, reporting;

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
    {'min_ver' : '0.0.0',  'fix_ver': '9.8.4.34'},
    {'min_ver' : '9.9.0',  'fix_ver': '9.9.2.85'},
    {'min_ver' : '9.10.0',  'max_ver': '9.10.9999', 'fix_ver': '9.12.4.13'},
    {'min_ver' : '9.12.0',  'fix_ver': '9.12.4.13'},
    {'min_ver' : '9.13.0',  'fix_ver': '9.13.1.21'},
    {'min_ver' : '9.14.0',  'fix_ver': '9.14.2.8'},
    {'min_ver' : '9.15.0',  'fix_ver': '9.15.1.15'}
  ];

workarounds = make_list(CISCO_WORKAROUNDS['IKEv2_enabled'],CISCO_WORKAROUNDS['ssl_vpn'] );

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu44910, CSCvu75581, CSCvu83309, CSCvv13835, CSCvw53796',
  'xss'      , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  vuln_ranges:vuln_ranges
);
  