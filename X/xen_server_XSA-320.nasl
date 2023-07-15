##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149085);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/30");

  script_cve_id("CVE-2020-0543");

  script_name(english:"Xen Speculative Side Channel Information Disclosure (XSA-320)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by an issue.
Incomplete cleanup from specific special register read operations in some Intel(R) Processors may allow an authenticated
user to potentially enable information disclosure via local access. An attacker, which could include a malicious
untrusted user process on a trusted guest, or an untrusted guest, can sample the contents of certain off-core accesses
by other cores in the system. Only x86 processors are vulnerable. ARM processors are not believed to be vulnerable.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-320.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0543");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app = 'Xen Hypervisor';
var app_info = vcf::xen_hypervisor::get_app_info(app:app);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var fixes;

fixes['4.9']['fixed_ver']           = '4.9.4';
fixes['4.9']['fixed_ver_display']   = '4.9.4 (changeset 80d78ac)';
fixes['4.9']['affected_ver_regex']  = "^4\.9([^0-9]|$)";
fixes['4.9']['affected_changesets'] = make_list('ad0c1a0', '04af886',
  '93cc305', '45c9073', '773686b', '4e79375', '8d26adc', 'b3718b7',
  'cf2e9cc', '43ab30b', '55bd90d', '173e805', '248f22e', 'ec229c2',
  'e879bfe', 'ce126c9', '4b69427', '8d1ee9f', 'e60b3a9', '25f5530',
  '49db55f', 'fa34ed5', '704f7ec', 'a930a74', '8c52ee2', '2e15a19',
  '70639ac', 'c3b479d', 'e349eae', '632fb4e', '4608c6d', '7daacca',
  '859e48e', '5be2dd0', 'b0147bd', 'cadd66a', 'd3c4b60', 'd59f5c4',
  '44303c6', '79538ba', '80c3157', '73f1a55', 'bc20fb1', '754a531',
  '7b032c2', 'ff4fdf0', '8d2a688', 'b9013d7', 'bc8e5ec', '34907f5',
  'e70bf7e', 'fa0b891', '3a8177c', '04ec835', '8d63ec4', '1ff6b4d',
  'f092d86', 'e4b534f', '87c49fe', '19becb8', '43775c0', 'f6b0f33',
  'a17e75c', '67530e7', 'f804549', '84f81a8', '56aa239', '105db42',
  'd9da3ea', 'ac90240', '3db28b0', '9b6f1c0', '0c4bbad', '917d8d3',
  '3384ea4', '352421f', '04e9dcb', '1612f15', 'f952b1d', '63d9330',
  'f72414a', 'ac3a5f8', '1ae6b8e', '1dd3dcc', '7390fa1', '7e78dc4',
  '8fdfb1e', '55d36e2', '045f37c', 'dd7e637', '7a40b5b', 'f5acf97');

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4 (changeset ce05683)';
fixes['4.10']['affected_ver_regex']  = "^4\.10([^0-9]|$)";
fixes['4.10']['affected_changesets'] = make_list('934d6e1', '6e636f2',
  'dfc0b23', '2f83654', 'bf467cc', '6df4d40', 'e20bb58', 'a1a9b05',
  'afca67f', 'b922c44', 'b413732', '3d60903', 'b01c84e', '1e722e6',
  '59cf3a0', 'fabfce8', 'a4dd2fe', '6e63a6f', '24d62e1', 'cbedabf',
  '38e589d', 'a91b8fc', '3e0c316', '49a5d6e', '6cb1cb9', 'ba2776a',
  '9d143e8', 'fe8dab3', '07e546e', 'fefa5f9', 'c9f9ff7', '406d40d',
  'e489955', '37139f1', 'fde09cb', '804ba02', 'e8c3971', 'a8c4293',
  'aa40452', '1da3dab', 'e5632c4', '902e72d', '6a14610', 'ea815b2',
  '13ad331', '61b75d9', 'e70e7bf', 'e966e2e', 'dfa16a1', 'a71e199',
  'c98be9e', 'a548e10', 'd3c0e84', '53b1572', '7203f9a', '6d1659d',
  'a782173', '24e90db', '0824bc6', 'e6f3135', '3131bf9');

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4 (changeset 2b77729)';
fixes['4.11']['affected_ver_regex']  = "^4\.11([^0-9]|$)";
fixes['4.11']['affected_changesets'] = make_list('9be7992', 'b8d476a',
  '1c751c4', '7dd2ac3', 'a58bba2', '7d8fa6a', '4777208', '48e8564',
  '2efca7e', 'afe82f5', 'e84b634', '96a8b5b');

fixes['4.12']['fixed_ver']           = '4.12.3';
fixes['4.12']['fixed_ver_display']   = '4.12.3 (changeset d58c48d)';
fixes['4.12']['affected_ver_regex']  = "^4\.12([^0-9]|$)";
fixes['4.12']['affected_changesets'] = make_list('199ae1f', '9dc2842',
  '09b6112');

fixes['4.13']['fixed_ver']           = '4.13.1';
fixes['4.13']['fixed_ver_display']   = '4.13.1 (changeset d8e1053)';
fixes['4.13']['affected_ver_regex']  = "^4\.13([^0-9]|$)";
fixes['4.13']['affected_changesets'] = make_list('67958a1', '9aefa01',
  '6278553');

fixes['4.14']['fixed_ver']           = '4.14.0';
fixes['4.14']['fixed_ver_display']   = '4.14.0-rc (changeset 7028534)';
fixes['4.14']['affected_ver_regex']  = "^4\.14([^0-9]|$)";
fixes['4.14']['affected_changesets'] = make_list('ceaae74', '6a49b9a',
  'caab85a', '058023b', '30a72f0', '1a58d8d', '31a714d', 'f7039ee',
  '1fe4066', '985ba41', '835d8d6', '63b4c9b', '16c36d2', '03dc5f0',
  '11ba5cd', '726c78d', '75131ad');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_NOTE);
