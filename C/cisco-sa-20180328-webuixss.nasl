#TRUSTED 1d6d2a23b9a334a90b7f468fe240be5a1071c68d58df976bf9e7179afb0fd23a4ddfde2debaa2ba2bd3748e19a89c8ebe3dd74e69478a00d1495ba0eee13e4d99df1e6a0ce1b0d3265f197531725a7ea451a67f8182b34e253a0b489bdd0258435bd9520c2be679dc673ae874276e82822a49017751f5b57d8e79d30257b98d9a7731bc6519e1e4fa3be98aab97b36a3e846c0ceab8e2697305e486361f7f5722ae108f159155f5a60e4927a42b3dfb1f7c9b65567b46ae82e2a002a1b3a4e5bd25fcd441d94b0a08d086dc69a422bd9dafaf7a228c9be031ed72a22a8551422156b0983c3a0141ff9ec0afc3e08961c170aff1dbba577ead9e23edce68d39b536c6c365974325d924d54c8570da0b5be066a9f62881d730a7139abcb41f79011a42041077eb3429aae634e8a87ad74c7ff6f7ffe034d45c36c47bf8b21f79bb4b013620b6166e194131aba710fa7d56d452a3b4b8eefca48da4a78530136a7df1f557309fbda09f93ac5802f8c894786ab59bdd06122e68a50628623a99ef4cd1a2c716a1b3ad8679019af1bb521aadceffae257d7d2f07b01ba9035e5f1729daca8ae8dcb59ee68550a99c06cd9573ceb1bd928382e12cdaa99e81d98be87626671a820154703861f17ed2f4c8c2fcf5615824ff935ba50118e23bae93c9caf9e4ecbe38817c507e6c17974b0d2d704f27fe6611a715d5a00365683008a182
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132033);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0186", "CVE-2018-0188", "CVE-2018-0190");
  script_bugtraq_id(103551);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz38591");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb09530");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb10022");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-webuixss");

  script_name(english:"Cisco IOS XE Software Web UI Cross-Site Scripting Multiple Vulnerabilities (cisco-sa-20180328-webuixss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by multiple cross-site scripting (XSS)
vulnerabilities in the web-based user interface (web UI) due to insufficient input validation of certain parameters
that are passed to the affected software via the web UI. An unauthenticated, remote attacker can exploit this, by
persuading a user of the affected UI to access a malicious link or by intercepting a user request for the affected UI
and injecting malicious code into the request. This would allow the attacker to execute arbitrary script code in the
context of the affected UI or allow the attacker to access sensitive browser-based information on the user's system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-webuixss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c03922e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz38591");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb09530");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb10022");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuz38591, CSCvb09530, and CSCvb10022.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0186");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_ranges = [{ 'min_ver' : '16.1', 'fix_ver' : '16.3.6' }];

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuz38591, CSCvb09530, CSCvb10022',
  'cmds'     , make_list('show running-config'),
  'xss'      , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
