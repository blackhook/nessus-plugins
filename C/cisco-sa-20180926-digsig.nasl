#TRUSTED 9455f1461bec5e12368834f049f1163e9a86c1fa3c864c3f93eb61816d7e0310e5e7451c8b5eda34fe5786ecfdd01f06e9a09514d37aa97ab2e2478758c1847f8aab066153f1781282d79d41d7e1f566584da0ce2784b6a8bab2e0b012f16632cb2b469503c29d24d00d4eac92aa30cec974a6382b3a89d43e94766e138dbf4d2623f93fa0713929512477b52c0af1d8c643e64306576c8549fccc02d2c4aaeda6a21cccf7bd896e3db0df1473b8790e3ef8730f83dff6d72459c18341f2167ddbc1e7e64503ec7e332d3b8d854ba850bf004917f19c1cd72f9ab706534a8fe76dcbbe9a6dba42f1d2b905db2eceb1df66d5d9a2debaffd487cdb1babb395b77d39c7eb8a9b91e1ba4af38e0ce4c6c6c1953554cd3c2e2bca9962877997f20b69c4a559f086ddaa76cba4b177b73d4c40cb50106ba65b92eee847851fd354870a6245dc753b1745729f41cd29ebe247a5260e711bd31665524195487f9ca2db4b919b53530ba825308d906c1ef8f2dd96f3a7fd41b5d05195c30e6a1b5d6632c5b6833a3b028c46c743f63c149dbdda1d15c14cc67ab01facc5354e22a509b43d4190787c5ba1ada7841bcb0a63599f483b33789fb10150d9a648f281206eee25747858f95e0fd551a70dc65894a9b59e0bd0d7248f84cb06e088433c0f89daf2fa1dd29ea1a0bacfdfd8aac8b346b0927036c17aa5bd81fe8e46d21e2f74ca5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132041);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-15374");
  script_bugtraq_id(105415);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh15737");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-digsig");

  script_name(english:"Cisco IOS XE Software Digital Signature Verification Bypass (cisco-sa-20180926-digsig)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a digital signature verification bypass
vulnerability in the Image Verification feature. An authenticated, local attacker can exploit this, by uploading a
malicious software image or file to an affected device, in order to bypass digital signature verification checks for
software images and files to install a malicious software image or file.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-digsig
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5094f8e6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh15737");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvh15737.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0); 
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.9.1b'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh15737'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
