#TRUSTED 651faed13f32ff02e19b95a9ea19383cb93b5efe2c9a23437971e6ce7482603bd4b0028ac558762324468d0a8e3ffdc4460a0d208ecf726c90dde5ebac63b8a8c3eec51bb9ab92f73876de1c2bc6ec687cab021d63237594d4d6efa215afd9e5f57821da8fdaffa717121f958e5a6c41589a19f78d8cf9b39cc3e83295383489a1e2ae14707dc1068f60fc0aaa87280c0482ce7f14806bb5e817e2d5e107dbfa5adc83a55d009153b559b0e95c344037d3fac27e77e4f5b0903bb68e4877f71151929465e76e1e45dd8c55095efb959d517f0880e9df39bd1c975f8d6fed5f80e0d1b6d39f4990597ead8cc27f4eea141462b3de35ecbadef11f5c7990c26189bdc4afd96e779ec4a8599774a1721a355b7461f08ed6758df8211e35f0211218ccf080cc45e0fae84ea876f9d01c8d4068fc4052cf5d59ffe5069bffc82be8d58edf5e24550ba3cfdee36e0ffcb0362016693be301d3c4461f605565efa80cea50c6ee4674ab9bee351f35f367b0412d79625674ab724ce3df0195d40e6f7f93fe7328a4726945a5323cf98867df3169f2d4499613d00ebc7d2fd5cd9fc22d7740bf1c3262ee46cdaedabb82be439aeb3403cd5e2475ba51a976416f38755407fdd73d3211b8ec46b16bf21880430e2d46ae02e16ca6ee1392d3adc651ce186bd031ce6756e85290aecb8a426e2b3fe1ab26e4cafc41ccd9978b3c21b73753f8
#TRUST-RSA-SHA256 4c406e59451424929b219202baf1a6e26e5d8fe7a093b5490892910633997604b203b325f56c4a493b5c447f3ea91a5b130950c3283035f75036f0384f85e318dd400f50ae89b3b1c16184a583d2e880ea9b3a61152a619fbdaedbc5855ed17a743a75625fdc5e4c3435b240946d1342804254b7b2ef0731503601c4e8e2bdf6df69882f2f99e9b05fa12b845de541a2ce35e5f985f39e24312ebc85b0b3092532e6da7dbb142e8b131f2115eb862419acb48722865af21d557c45b613677089d4cc74456dc040fdf9072aba8359ed6feefb4aa0f2e7b04e04a4c23918073eb141c2f2d31e23d60e391669e0e9ef79620d36bee3791f3b1005d95b6d6ecb4254b11d99bc95fc92e13445203d41f4d79761f20d854f7d9c5d97f82d5787738062567be4ca4491a4cb497ac5ee9a00b47904fb1a7a7e4433b22fa8012db3d16aa9a381a46bf1f5dd0510ca0f1ae676fc862576be7d2a474dea66d4bc54f24fe36bb336aeee78b077ff36cb0dbf99eb8cdd364221811324d3d10e211ac67c2e0c298b8b40b66716e3641608e372d94861a0755d1613f3fe0776def4b41a57d423b0ddea0964c70b89731cb82c8dcae45c7eaadc3466cd1ea958b8d5c597695b5f8486949cfcedf496351616112382a298c5112aa95fcbbe2ade7cf666351bb36a829b2cd4ca81f0da59db9e73c468823b7ead5b84016a599231e6b93fc6179fb828
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149371);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-1448");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt74832");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv78677");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-cmdinj-vWY5wqZT");
  script_xref(name:"IAVA", value:"2021-A-0205-S");

  script_name(english:"Cisco Firepower Threat Defense Software Command Injection (cisco-sa-ftd-cmdinj-vWY5wqZT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a software command injection vulnerability.
A vulnerability in the CLI of Cisco Firepower Threat Defense (FTD) Software could allow an authenticated, local
attacker to execute arbitrary commands with root privileges on the underlying operating system of an affected device
that is running in multi-instance mode. This vulnerability is due to insufficient validation of user-supplied command
arguments. An attacker could exploit this vulnerability by submitting crafted input to the affected command. A
successful exploit could allow the attacker to execute commands on the underlying operating system with root
privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-cmdinj-vWY5wqZT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7585c998");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74594");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt74832");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv78677");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt74832, CSCvv78677");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1448");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/11");

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

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

# Firepower 4100, 9300 Series appliances
var model = product_info.model;
if (empty_or_null(model))
model = get_kb_item('installed_sw/Cisco Firepower Threat Defense/Lw$$/Chassis Model Number');
if (model !~ "(FPR|Firepower)\s*(9(K|3[0-9]{2})|4(K|1[0-9]{2}))")
  audit(AUDIT_HOST_NOT, 'an affected model');

if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD', product_info['version']);

var vuln_ranges = [
  {'min_ver': '6.4.0', 'fix_ver': '6.4.0.10'},
  {'min_ver': '6.5.0', 'fix_ver': '6.5.0.5'},
  {'min_ver': '6.6.0', 'fix_ver': '6.6.1'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt74832, CSCvv78677'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
