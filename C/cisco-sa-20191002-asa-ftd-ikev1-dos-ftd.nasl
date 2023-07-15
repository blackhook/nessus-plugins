#TRUSTED 95f5b55aaa1e71a36ad55db14dbfbac8bb1e80983d119031a8b9e5f63d23201dbb4837b65031854d98d050b56754871e98c1245da2fb086a765cf33eaca6ed87731659b1b323697ced0f89e86fddc69d9b418211e46d3b208ec09876db5d6a1be9015d1836e518939741495b9ad3cdc8dbbb8e4c196c8ac3a32f9288832a31d2d735d488f22c169d42f88fb37ddd8f0869447d187af6f07d962dba9a87b3df329d1e033872be4bb420acb36e24c953de035a2891bd5be0468c8a14beba8a5111085ff70e26614b22f62b2170f4ad9b49eec332adf8b1bce174faee128983dae52c0c41b269f5bb430b87580ff3853ee3f3142c114bc5509a139fd08d5bbd66c551b7f8a3292c2507bcfdb0630cd4e623980086e17c4b2556a0d0398d9b1194c25feb8fe488a0bfc58f131e5144bd4a9a06dcf9cd156e7105a18b83f9eccd17103b3a10cd9f865153ad3e9913d74b6cc94042db61820d6d912103f253ddabd0d60a97cebf48a81a591b911e9f22392e7ceb7e0bc69825a097b5b20ea70ef22bf8882be2c9f05293b3b5bb5d580a4d72ed015683fcfe575925bf3c727ece8feb42b3f2eb4dfc8673bcfe9689dfca02fe5b8ca88b9a99132717b30c6ef58329e8b57f04caa0bc75b9b931a03c9543534b89370c894b530ca3e3473ffad5e913c301d445dc0ffd6dcd83112364566d276d15dddec6c3bbc66aba49920d3b4dcc2f63
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133842);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/27");

  script_cve_id("CVE-2019-15256");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo11077");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-asa-ftd-ikev1-dos");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco Firepower Threat Defense (FTD) Software IKEv1 DoS (cisco-sa-20191002-asa-ftd-ikev1-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The packet inspection software installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version the Cisco Firepower Threat Defense (FTD) Software running on the remote device
is affected by a denial of service (DoS) vulnerability in the Internet Key Exchange version 1 (IKEv1) feature of Cisco
Firepower Threat Defense (FTD) Software. The vulnerability is due to improper management of system memory when handling
IKEv1 traffic. An unauthenticated, remote attacker can exploit this, via malicious IKEv1 traffic, to cause a reload of
the affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-asa-ftd-ikev1-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2df7518b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo11077");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a fixed version referenced in the Cisco advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15256");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '6.2.0',  'fix_ver' : '6.2.3.11'},
  {'min_ver' : '6.3.0',  'fix_ver' : '6.3.0.2'}
];

is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
  else
  {
    workarounds = make_list();
    workaround_params = make_list();
    extra = 'Note that Nessus was unable to check for workarounds';
  }
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['IKEv1_enabled'];
  cmds = make_list('show running-config');
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo11077',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
