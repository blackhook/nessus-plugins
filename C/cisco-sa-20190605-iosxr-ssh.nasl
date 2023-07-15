#TRUSTED 4ed7fa9ef739f7d86d9dbcd54a51617f554d45b41c3219fbe585b49caabca95af1a52dcfe2180b4248dfa3df451c864f1b2b7969ab067ae7a7cb18fab6d0d970e9ff1092dfc9d5e5b8c0cf08ceea62d5ce42a267d55fc0e62f97a0f8477b78a65171fe88468c65ccc963182ada5c467d30975094e81803c5b9c10387c29b9e9f5a56c138c8ce34235a7b2d4394957e4f40a48728cd271e5c6c67968a81a65b7102c14e515efe417d756437d0162e7c32e14ef671be9873ba4a0c0c4dd7b36045f5c1b24f55ee3d6fcda787e036cbc691f7a76faf57ab78d015abdcea13be8e98eb015e5348cfbbc448edc180d3c75d716fd3d9ac4dd001771daba63b4d401ec28e9e1f7787742569ac22328253d793794ab5b41fd082b2cb25e619050389212909f07970add86398ad88b954c822681892f43ecfabcede5c439509bc9b5d8db5eebcbd504e3c685107a1f82936513db9c970c4dad43ee2a2cbbb8971babef64a1b2ee3da4197813129e9bb8c23eb75e5e12e267c4d99d5a29a3306a365261a76c66a4749edbbd934b626af18bcd9f54dfd99fcdf0b7909eceea583c446ea38332c1207c7b2186fdc80c413ae2ff314fb6af6d8079104e33de045038c379d5b9307d3c8fda8289f62e9920cb1d5227661cf39403f6f8d45900f23209e029fb58b933d96c049258650b888736f8fe6296616517add1118037953f5d5b2534f5d62
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134173);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2019-1842");
  script_bugtraq_id(108687);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo03672");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190605-iosxr-ssh");

  script_name(english:"Cisco IOS XR Software Secure Shell Authentication Vulnerability (cisco-sa-20190605-iosxr-ssh)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a vulnerability in the Secure Shell (SSH) 
authentication function of Cisco IOS XR Software that could allow an authenticated, remote attacker to successfully log 
in to an affected device using two distinct usernames. The vulnerability is due to a logic error that may occur when
certain sequences of actions are processed during an SSH login event on the affected device. An attacker could exploit
this vulnerability by initiating an SSH session to the device with a specific sequence that presents the two usernames. 
A successful exploit could result in logging data misrepresentation, user enumeration, or, in certain circumstances, a
command authorization bypass.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190605-iosxr-ssh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ceea601b");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo03672
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?344ac16c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo03672");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1842");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

cisco_bug_id = 'CSCvo03672';
if ('ASR9K-PX' >< model)
{
  smus['6.1.4'] = cisco_bug_id;
  smus['6.3.3'] = cisco_bug_id;
  smus['6.5.2'] = cisco_bug_id;
}
else if ('ASR9K-X64' >< model)
{
  smus['6.5.2'] = cisco_bug_id;
}
else if ('CRS-PX' >< model)
{
  smus['6.1.4'] = cisco_bug_id;
}
else if ('NCS5500' >< model)
{
  smus['6.3.3'] = cisco_bug_id;
  smus['6.5.2'] = cisco_bug_id;
}
else if ('NCS6K' >< model)
{
  smus['6.3.3'] = cisco_bug_id;
  smus['6.4.2'] = cisco_bug_id;
}

vuln_ranges = [
  {'min_ver' : '0', 'fix_ver' : '6.5.3'},
  {'min_ver' : '6.6.0', 'fix_ver' : '6.6.2'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cisco_bug_id
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);

