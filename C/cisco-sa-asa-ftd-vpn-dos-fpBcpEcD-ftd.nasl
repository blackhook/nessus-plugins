#TRUSTED 2dd5e73cb889799a2584cc4b72324632fee4bf7cd0c74aee599cfe4d239896414624c42736ff693483d3968f2cf8af332e4032142f6010fb7f751da1fe8f75fe46290b9967e42ca11dbbe4521af3b6fa1503dfdf48e52177ffbf41c111b8fb7fc58feddb4b6491966f7030abfbcfae69bf16f4b35151235df10e0ef1e3e8fd5d6276ff496f6f2b0826f23e86c9a6ff486ee192b952f5daea4e5adaa1941b20c49180b301a5904e2523a3107df5c30acf35f0f634603cfe61427fb24014ff619cd742a4edffaa963dbc5134668fe4a706992f7a28fac5351364eb86ff9d6b57027f466c80f8ab9b027b0576eb6dd3982c43f2180a9890d1938507d6e5e9c0a6edcf325e155d5ff36dd91fad7add961a8ccaab2f76f65fec94be2e1dd03c7d8458fdbb6b91f6f9694eca6e71c13f1a304878fe2984c886ed8b05750b85f3c2c8bca47c576deb44fe50b758e716bb39e88ec548f6fea2f3b044884d9ac982c0a74cc0cfa8a21945abfc4bd860dedf154d62811a44d86677a6cbb005de4e0320468c9ae56578ff7cac5ebbc5abc8b707e483c5fddb1bd4d16729c2aa18e749c5f55538a7ca3e9e52bc7ca53ea0b227a37ca4b80d61bf359bdc2f30d0227f62c28655a9cd3858c0b065cdbf435748b9519b4a633d2c9fc2043854562ec6e1720f5878cf2ff5b81ead00c980923c2aade95dcf0d1ca428f8618199ed5444cf805f2b55
#TRUST-RSA-SHA256 85fe85674c671f308e042380246bf8553991122af895abbcb2a76f4f71b39bc39eb576f7df4aa95c84a42d292328f03d2bb7bca53e474df6f852a1a4b7c0ba59941afc38dd9aee2cb6efb0b913b9c0724e9391e23d3fa6219f3a45111920249c859e7b4e5dff5242e0916c44435d3d49ead04aad39d28e07fd385747025d12662583c172c26b89632bb853f63bb5ff419beab1fd675afa5752b0f015f83dcee4fc20a6d5e760abcefa784fbafa196a4b497c43b7ee509339f5b9ae65a77ceb79fcc07a1fa5b0b8e6045be81ed72cd655b0b847cfdd3b7560dc78304924a93889ab64138be3e823be6f478a652af3eb81301da7e3a89bb3469b7f170d26bc81527c41996f30d8296f4f4aad50b0ccb88eaf5dcea5bc499da2e5333a48edcea294019d9f8d71915066608cfe1290d028b99aea6e6417d8237e715b781ff6e78c0ac916c2a546105db507b545ab410dc4166b196392531d5a1b90a264e97c80ceec78a0d7fbf347da604a81368722d778b0ae898b5e60339d39593abebf3ca90dbf09c2f5d6d51bd1b3bd1ff8cca94d3a5e49c23712c9a4e89111e2f283e1d6373c699871839de82679108165c6774efa7b5c5b2abc6c1d13dca222d1c859128cf5ec44b1589b8b8efb87d2b005816f94b17c3b9bf713a9f9dfb403d31c9255685ee25ea9463e72ee668a858b96351113c4db0f66a14af9bcba6fa4025923892b2b
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149303);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-1445", "CVE-2021-1504");
  script_xref(name:"IAVA", value:"2021-A-0205-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv56644");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv65184");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-vpn-dos-fpBcpEcD");

  script_name(english:"Cisco Firepower Threat Defense Software Multiple DoS (cisco-sa-asa-ftd-vpn-dos-fpBcpEcD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by multiple denial of service (DoS) 
vulnerabilities. A vulnerability exists due to a lack of proper input validation. An unauthenticated, remote attacker 
can exploit this issue, via carefully crafted HTTPS request to an affected device, to cause the affected device to 
reload.  Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-vpn-dos-fpBcpEcD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e9b06b9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74594");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv56644");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv65184");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv56644, CSCvv65184");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info, vuln_ranges, workarounds, reporting, is_ftd_cli, extra, cmds;

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.12'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.4'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.1'}
];


is_ftd_cli = get_kb_item('Host/Cisco/Firepower/is_ftd_cli');
if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

  workarounds = make_list();
  extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['anyconnect_client_services'], CISCO_WORKAROUNDS['ssl_vpn']);
  cmds = make_list('show running-config');
}
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv56644, CSCvv65184',
  'cmds' , make_list('show running-config')
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
