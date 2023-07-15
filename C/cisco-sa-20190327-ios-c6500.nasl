#TRUSTED 029ffff66baece4131eb1f329c321eced117c1812b572cd9bcc756a556c308db33a9acb9cedcba59b6a330d1e79dad41ef07d698e1fd2d0296ff24acbbe9921955449961175399f6b7d52dfb956418cae4dc7ac55671e4eb23ca91f47228a5431de4e9dda4d3775e20c9563139d0d1ae14af1a100fa71706a31caab62d8969144d13d8d4ade8ffc1f83ce54f9433d5982aaa6fead6f725a30f2c4a78613cc31e129bae34c6a68a4ea180fcf297e81466e6d79f5c6f4aba0d346cd173b8aa711e372fc15cc05d5403574d48f02115a0bf6515f26776ccbe1159e642836127635e69ad96f33da938559aa47cd7029529bc426c767b7d53064238ab933fbd30ba4bc2b25a97f80160240bea2b119d06d8ba72707121a2069fb92c9141380e9999047b6f59ffc0cd823fbd9434a63fd9b76b2d528bb355e002001fba2fd90656f4ab4509e1766de7b7d8fcb5535959495ad334696f0fdb8898ff5b8e62f4abeea155f99fb6cdd271f13629d43cfe132eb222c94db5f2afbfecbe5e5614a136b7e93a06a66fe20cbbc965c143c2b128b20bf04aed46656fc5b9e0bea6cce5c8e475f8dbd86e242efff432794c08b658e41ef5d07fb29c1992d27153e61cbce9e4cd1d7762bd37a53127f32fac0a1f548322ac88ab49f096a20ea75bbf903a3ab42659e233fc0cf7f0f6f41f14dd6d19b25f193a5e29917738e6118484f8eb49f49b8c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134951);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2019-1758");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk25074");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-ios-c6500");

  script_name(english:"Cisco IOS Software Catalyst 6500 Series 802.1x Authentication Bypass (cisco-sa-20190327-c6500)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is affected by a vulnerability 
in the 802.1x function on Catalyst 6500 Series Switches due to how the 802.1x packets are 
handled in the process path. An unauthenticated, adjacent attacker can exploit this, 
by attempting to connect to the network on an 802.1x configured port, in order to intermittently 
obtain access to the network.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-c6500
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b826d15");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk25074");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk25074");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1758");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(665);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

model = product_info['model'];
if( 'catalyst' >!< tolower(model) || (model !~ '65[0-9]{2}' )) audit(AUDIT_HOST_NOT, "an affected model");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version_list=make_list(
  '12.2(33)SXJ6',
  '12.2(33)SXJ7',
  '12.2(33)SXJ8',
  '12.2(33)SXJ9',
  '12.2(33)SXJ10',
  '15.1(1)SY1',
  '15.1(2)SY',
  '15.1(2)SY1',
  '15.1(2)SY2',
  '15.1(1)SY2',
  '15.1(1)SY3',
  '15.1(2)SY3',
  '15.1(1)SY4',
  '15.1(2)SY4',
  '15.1(1)SY5',
  '15.1(2)SY5',
  '15.1(2)SY4a',
  '15.1(1)SY6',
  '15.1(2)SY6',
  '15.1(2)SY7',
  '15.1(2)SY8',
  '15.1(2)SY9',
  '15.1(2)SY10',
  '15.1(2)SY11',
  '15.1(2)SY12',
  '15.1(2)SY13',
  '15.2(1)SY',
  '15.2(1)SY1',
  '15.2(1)SY0a',
  '15.2(1)SY2',
  '15.2(2)SY',
  '15.2(1)SY1a',
  '15.2(2)SY1',
  '15.2(2)SY2',
  '15.2(1)SY3',
  '15.2(1)SY4',
  '15.2(2)SY3',
  '15.2(1)SY5',
  '15.2(1)SY6',
  '15.2(1)SY7',
  '15.3(1)SY',
  '15.3(0)SY',
  '15.3(1)SY1',
  '15.3(1)SY2',
  '15.4(1)SY',
  '15.4(1)SY1',
  '15.4(1)SY2',
  '15.4(1)SY3',
  '15.4(1)SY4',
  '15.5(1)SY',
  '15.5(1)SY1',
  '15.5(1)SY2'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk25074'
);

cisco::check_and_report(
  product_info      : product_info, 
  workarounds       : workarounds, 
  workaround_params : workaround_params, 
  reporting         : reporting, 
  vuln_versions     : version_list,
  switch_only       : TRUE
);
