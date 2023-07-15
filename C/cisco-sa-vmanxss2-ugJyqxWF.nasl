#TRUSTED 6b4beea5db35718cfc0fc02a5680a436cccb4fd5d8feea61db58fee82f4a34c2a5441ca11f1461f8b0281dec011b9e76df51149f13cb03ea844f5159adbfb7643a7da4681c14835f081a01305c582c067536346d656f2ecc6461ff3ed826977a732eea45d95e0d9bbddd896e7775bee5dfeb6689b7dcb2e3a8acb116a46ac22111a6bfddacc83b53123aa20c22fbc2eb91cd8cb6b85951f2d3c4a89274de6d4f24f6d7afe91638095a850a6475b2d38c61402ae92260747e35486a4825564e625f1cdf4e30a3b9e4e4a2a12d893f044c4697dab6345e32ad416ec2ad6a7ed0a3e4604e851369339728c2e8466acf231adab4cefdfb79153c968f23a0655786c194ba7b6a1ba3d8a3ed91d6a5d05034e7cbb3703ecbe3fa4fd07f52202654c50d8e06f18aef49f50748e80b6bee9009ea6bf3c6acaa9c3233225d2b44a12559ccf7cb341513d9f14787ccf5566e1e77f61cb0736f7e90f3fb8e4eadad26ff6f902701ec28912deb7f1a7e25b9ea02ec807d4fea36c655498c544f98db080f7eb7320083a94557c2d679e2aa7a1d7a26b8e2af186d80e545fed68c9ef56eb75aca0a8c58ebfe506b1b29312c03cfb69d6bd03a958a904111a8e428cdbbe0824c226d1729a0222acb74efb9a8564be59d5e4e2b060975e400137e2e6b4439319bc716611e7646b0da201a237bf4afb74176172f73086d2d6a0f30a27a86a5c58511
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143165);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id("CVE-2020-3587");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv42616");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanxss2-ugJyqxWF");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software XSS (cisco-sa-vmanxss2-ugJyqxWF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a cross-site scripting (XSS) vulnerability
in the web-based management interface due to not properly validating user-supplied input. An authenticated, remote
attacker can exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a
user's browser session.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanxss2-ugJyqxWF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8aab83ed");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv42616");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv42616.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3587");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'20.1.0', 'fix_ver':'20.1.2' }
];

version_list=make_list(
  '20.1.12',
  '20.3.1'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv42616',
  'fix'      , 'See vendor advisory',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
