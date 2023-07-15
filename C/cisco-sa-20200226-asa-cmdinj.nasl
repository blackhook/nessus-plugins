#TRUSTED 2ddc4b12e0eff94760020331a5b4f84d3d523c71205455af43a96642f74361396543de2320ac43680d375833030a9277dab4f68a5cd86041819428eb61257d48012377cd87577a1d171f1920b883a986cfdbad2ddcec9116bb5e001ab7daa945f15cac6ecb1d4c742bf333ca0ae000420547de5f163d463b791ac5f2e62eaa7aca361725a494e050a365d530b3d339e1bc0d874197376bbf56845bc66e5ae20f4dbc956d909e4c1731b82d93c5c1b9ff19d7634ce844ef56ed26ec1d315f66a620bc8a60961a41126de3b13c5f108b4157932b8b9ba63a37fc94bf2aa95f1965a13f254a72c839960a8e8c47be36a5d588bb777f01dc7aa62a925f586f9b6c74f8cbc607bcb0b6e9b9447722f4f3f6d6f2eeacf3cbec6743036bf0102957ef463bd19aeaeedc5a41f5a01cc5e7bb1899b4467b29d2ab292ba47c51e904ea8d483b72badc0e7b55c9f30a947fc610696c964facdd96c32a4011d619cb83d705621ddd0ca1395b0d8481631b30b9f4ef19a8ccd6cc018de812601aab08bf62405343b1fa90a7088709c6fbfb2a979388efe533e85125407df4a2806461502ca8ed181a5901b1b5ca4894c7849a4b23dd02b5267c5b3c5360afc6cbda477fca8909df26835eb9272c64368de391d09374bec00f028a29121314b4a22cb28245ea6703945555f5a16eba2b56346bacbb01a8f1a5c5f139952a713983e12f4db4b80d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134565);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_cve_id("CVE-2020-3167");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr49734");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fxos-ucs-cmdinj");
  script_xref(name:"IAVA", value:"2020-A-0085");

  script_name(english:"Cisco ASA Software CLI Command Injection (cisco-sa-20200226-fxos-ucs-cmdinj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability in the CLI due to
insufficient input validation. An authenticated, local attacker can exploit this, by including crafted arguments to
specific commands, in order to execute arbitrary commands on the underlying OS with the privileges of the currently
logged-in user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-fxos-ucs-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5d34d6d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr49734");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr49734.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3167");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

if (product_info['model'] !~ "^(10|21)[0-9]{2}")
 audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '9.8',  'fix_ver' : '9.9.2.66'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.37'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.3.7'},
  {'min_ver' : '9.13',  'fix_ver' : '9.13.1.7'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr49734',
  'disable_caveat', TRUE
);


cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
