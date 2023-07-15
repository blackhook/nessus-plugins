#TRUSTED 77379511ecc3df284678530ccb1627276298eec0403c09328516477388605e0be863768c5c169d90b51fc74cb1430124e22795da11c093870d25f35a55702bd3afaca17352e031bc33a1e819a30c1ed7413caa7edf839c21aa84897e67b1d175b91b75dba0507ac9c7cb92e50ff94b08f9790e7b3fa616cdf586f868b7c177a0a5408cf231dc503e0872c6c107974410aab9350aa1818f05bc9adfd9e0473de96af3a0d2ce23c3911fe4d1233f35c8aed614ed8722784b9d1e7f5fab86cb6a6de94c5802f41ab23f1a27e658065b24a69900e794a5627ad1f6aed521d1b82d1da02a15bcf4a86ed1a01f2e358dc86bcd74b4e8a443bcdf08bdd0a353683eb82e5faed567861dcb65e8634c83251973df533602e8a66dd76f23e1b5eb22f512d63b4c9b37be8cacdfcded4e7c3fe32a09978c0a647f2124a5f1eb4a7b6dcb9525d2ae6940fa7f2b7bd32f10611eec09814e70f56060df79191e9511b051ec7bddfd8594bc1a4c952ee88291b4964e1549b814b67542216015f73b61e2f5dcc3448a0a0850cf0b0e302ca9081ca76e9143b7512d50ba64463adcd20b293b941e74aa72c5836a6c577d3d3eb56d8667367d18222a98b6dfe138573a8718e638a0fb34fba11bb585e664941760bc2a0a71837e6b44ef51a9a448b9e80a8dcc0bec90341e9fdaa3bcd8be9c36c354eac674ac6c88cf215d507c544e1c4477adfb73d0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135295);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/13");

  script_cve_id("CVE-2019-12699");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm14277");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm14279");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm25813");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm25894");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42621");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42651");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo83496");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-fxos-cmd-inject");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco FXOS Software Command Injection (cisco-sa-20191002-fxos-cmd-inject)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by multiple vulnerabilities in the CLI due to
insufficient input validation. An unauthenticated, local attacker can exploit this, by including crafted arguments to
specific commands, in order to execute arbitrary commands on the underlying OS with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-fxos-cmd-inject
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ad074ec");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm14277");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm14279");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm25813");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm25894");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42621");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42651");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo83496");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version in the referenced Cisco bug IDs.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12699");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');

if(product_info['model'] !~ "^(41|93)[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '2.0',  'fix_ver': '2.2.2.101'},
  {'min_ver' : '2.3',  'fix_ver': '2.3.1.155'},
  {'min_ver' : '2.4',  'fix_ver': '2.4.1.238'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm14277, CSCvm14279, CSCvm25813, CSCvm25894, CSCvo42621, CSCvo42651, CSCvo83496'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
