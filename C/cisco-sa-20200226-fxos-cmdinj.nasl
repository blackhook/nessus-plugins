#TRUSTED 5a289838b148520895874cb49508b72f306a339fc02a9c320be86e89c2b372977076e195915309722864d01bd1a144aba718e09837c4f6ceb3328f82d1b210a3874845dc67a57d61fcbcfd65cfcdc4be620e51807d5a95d67fd45ea7307d1b372a4ad34a103253c62c81d008b694e65da7b102074c39b9fe573033d570157a076cdfc40ce877cd9f206442a5f4e9a02c7198b223c9f55bc8f1c8905fd2021f3c50fd5539db74095857607685650247a4336dc7e253bfee4fd52082740b8d0c0f8427cb26d75f3604ebfac16da737c5ac26a407fc6d0a5c80b156fbe0d291e53c3361ef9da8477403dd0f1a109121bd3fa1c4aeef2dd07379429251f67ac41e639496f3ec73d6715a056e23e342d868563866c32254175860652a9118b97af32594a595f1266f34410c400b3ecf5a1aadaf2210cf602098194cbc08bf553f55ca967cffb352291194a7703e347f8c6de7950ccc4f602802ebdf2b1a6a98838ce45dd580f42a74fa0f2fba6c7c71dccfd0ef803709fc6615845e43084f2028c8d198af8b9da19fa794c3e07c1cb0d1f06da1f304b0a4511d92da7964f1f743f6a9114d52601594f0bab412dd667a76f6a93aeefec0a050e423f3441a42c70d17b5ed761c213d1626d204fc095690cbd5146f0078ea318abc1eecf25cb5c7b3f8da9e7cb73ff904b7f698425881294dd400fb57567805c0dc30fc6731dcfed6c0be
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134567);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3167");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42628");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42636");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fxos-ucs-cmdinj");
  script_xref(name:"IAVA", value:"2020-A-0085");

  script_name(english:"Cisco FXOS Software CLI Command Injection (cisco-sa-20200226-fxos-ucs-cmdinj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by a vulnerability in the CLI due to
insufficient input validation. An authenticated, local attacker can exploit this, by including crafted arguments to
specific commands, in order to execute arbitrary commands on the underlying OS with the privileges of the currently
logged-in user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-fxos-ucs-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5d34d6d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42628");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42636");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvo42628 and CSCvo42636.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');
product_info['model'] = product_info['Model'];

if(product_info['model'] !~ "^(41|93)[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.2.2.97'},
  {'min_ver' : '2.3',  'fix_ver': '2.3.1.144'},
  {'min_ver' : '2.4',  'fix_ver': '2.4.1.234'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo42628, CSCvo42636',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
