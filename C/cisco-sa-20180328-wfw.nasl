#TRUSTED 88621877fc6a79416be67d133f42563d1fc9e95e8ada36cbd0276f1eac3108ffa13dc7fd46b945ef5d4791d6f7351046929bdb8903ba995412bf8ed272487c33cf32800691f3b0cc8d2cbc443776ce333b90feeef7099f8b8af81d7e2e519073c356dfd0b68414b85354a3f4a0d5aa7a56e6a83ef0f77222d925d2eda06a1d57dac74b653db2b79875573eaae809768f845dda91ddd89738d4368ee9e8208cd4174be7c73d5605d57df87bef27712acdb6a3d51174757ba1edbeca1188ca119218cbd3bdfc13b16cc3f51127483603f310594a2c42271c8b8669ad44474abb6fd480fd4d20d605ded4e25f0f12d2346aa265cd68a01ef81509f92ea22b14ea5531b5464b1979cab2f33b93b5ca7171e9b75945eb9c2b502b9d0742e606c0d97d07cfd5adc859170d3220f03c3c0cadf5fa1b39db7c3fee8ece0db48744f5e4ca80a13778efd4b796fa530203653dc2b9e9f060534de3d15c49a90d686026966267d70a45b3b549710fcf086a868b9210033458754d349ecd3c75a9e4ec3e834cf7a69e246246bb52347e9a6eb393b6327e397f326ea1f435c6375f3b773661736b02f01e6e3eb9b53473a347d8029b496b3c0285275eca47d7e2aa1a1a9670ba0d5d2579243030ce1014f4afdcc43f2b830151316de6427b9bd939275ed9f6233a721db185f10b8709a6f0335625babe5d3d5a73a98df4d5a25c4012e5491866
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132077);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0196");
  script_bugtraq_id(103570);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb22645");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-wfw");

  script_name(english:"Cisco IOS XE Software Arbitrary File Write (cisco-sa-20180328-wfw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an arbitrary file write vulnerability in
the web-based user interface (web UI) due to insufficient input validation of HTTP requests that are sent to the web
UI of the affected software. An authenticated, remote attacker can exploit this, by sending a malicious HTTP request to
the web UI of the affected software, in order to write arbitrary files to the operating system of an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-wfw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84cc9812");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb22645");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvb22645.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/17");

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

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

vuln_ranges = [
  {'min_ver' : '16.3',  'fix_ver' : '16.3.2'}
];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvb22645'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
