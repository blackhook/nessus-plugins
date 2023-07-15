#TRUSTED 89a1d5d5f0abca47c1b6a9903156596f1d4df09f5ef82fab2d3ceef3bb78ed5dce7afb37d1efd0806cd8cb2c31692e6083068d193a7124e355d41a2edd3113de60cea8557a465b007ea8dcd37da795dbf1f44decf7548ba3eef15b6be280482084cf7f4339488dcdfdb45a886469047057b7c32632ca206630926989e6848b40db3467bf2fcd1e93982233d1dfd5dcc3b6eb997652ed8a9876d97faf10f8279e969f4ac1c4c6ae2aa8be65b367cb2cbcafa1d524740c8642ecff300ee5919a1ca459369e847681b9b1322640314894ca9d288f6f7d36bd3828176d7eac7feb7a6838ecee59e6874d01d8297119a5b13efae62680ad329125715331d798d0b0dfb3333c27e2529aa4b2ff729c85778504a70740b127d725869cc98853e6b8befc3adc3fc47ac2b143a3766e7fbb7e6608a73c68802fbe0cf387deeb8a904b1877a9270ed70c5f19c64aebf357367dc50580a84e1cdb6515758b8d1b746171b2e11e0f1f38e172213492385a59c22ff44903662d6104303acf3ef7d7587642b8d8ea20dbdc7c5b47635a58099edeb45cd4694b4dc96bb65c58cbef0047aea4ea282abcc8fc0b5c44e8f3ed60a4671641ac23e8c0509f6acee4500f2075c72c91aeb2cdeb59cfb0974c986bbcacd3bdb86f22f4f5edad620f29c869ba60a913eb58ac0f7674da19a4d1519c658f5b0def5a1dd1d6800bdcc75e65d3bd32313e23cb
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129777);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12667");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk15284");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-xss");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Stored XSS (cisco-sa-20190925-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a stored cross-site scripting (XSS)
vulnerability in its web framework code. This allows an unauthenticated, remote attacker to conduct stored XSS attacks
against a user of the web interface of the affected software. The vulnerability is due to insufficient input validation
of some parameters that are passed to the web server of the affected software. An attacker can exploit this
vulnerability by convincing a user of the web interface to access a malicious link or by intercepting a user request for
the affected web interface and injecting malicious code into the request. A successful exploit allows the attacker to
execute arbitrary script code in the context of the affected web interface or allow the attacker to access sensitive
browser-based information.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e519691a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk15284");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk15284");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12667");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'cmds'     , make_list('show running-config'),
'bug_id'   , 'CSCvk15284'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
