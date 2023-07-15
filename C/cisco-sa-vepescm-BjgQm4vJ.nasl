#TRUSTED 2f7270cb35a54f61a8adfc982ea867c4ac0bfdc2fb7fceca62a423c0e1b6c07de40b85f5c36c3b0ad1d245735fb59da3b62e988bc82a5e58d29f2bc9711b8b6067499c2d462766e28c33e4b4208a88a65fcbf82c150a66993ad62e493ec2412477c27824e4ea3dbce1d5f777dcedfca3d2a6f4c761461a76197bd9fbbbee3d98820957b6f261255c7cce5a33a8b6da9f220cb1b2fdd5776d2a1d27fa2295beb0125657e15497b0bf33861e82c957f832740426bb10ce57aa56fb32234f16830e90233b48a814ba8a805363f93aa2419c7915f59119e59fd6ca268d1fdfc3c7d807846a9ebc2ee08a9e884bf8a067bf016915dd56696ecfab1f5acaacf7f221a9377fe56f530ac96751a89fb554c0647421ede7f85163599a72132933ecc50f544f201e887df4832b46cc2bed4c97841a75ae682c0bc7d14b801cd66b294c4b758e3948ff5893264fb4b36ed6ae6e32000bd5d8a43af184a81a387f0668a6f7e8628ddc1701192d1ba0be5ac6c6a834b2543dfc5e3bc33c10af7ba6627b85502f13887bd5c61938092b92f15bc58528d837e8217cace187cd81b723abe789007f12efa1ac6bf12c06c5a707d6ea5d3e5177f06a70e5f3c0b363c1cbab686cbf8c0fc807061b60ecda730f11e101f5411ab142fb585fcd0057cf1e2564ceacd683383860b41998b844edf089ecd6dce36e0af09704376b5900a70fc0c7f6883faf
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142659);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/17");

  script_cve_id("CVE-2020-3593");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu71921");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vepescm-BjgQm4vJ");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN Software Privilege Escalation (cisco-sa-vepescm-BjgQm4vJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN is affected by a privilege escalation vulnerability. An
authenticated, local attacker can exploit this, by sending a crafted request to a utility that is running on an affected
system, to gain root privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vepescm-BjgQm4vJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be13a722");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu71921");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu71921.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3593");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

vuln_ranges = [
  { 'min_ver':'0', 'fix_ver':'19.2.4' },
  { 'min_ver':'19.3', 'fix_ver':'20.1.2' },
  { 'min_ver':'20.3', 'fix_ver':'20.3.1' }
];

# 20.1.12 is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu71921',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
