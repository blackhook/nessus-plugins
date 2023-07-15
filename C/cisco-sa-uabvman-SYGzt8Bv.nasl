#TRUSTED 034a0e1362e8e9cce61b1e2e8e88b4c305ab16518a4c9877f07cede630ad329175d3cf7039c6b124cc7ca853c07d3e9a86e263f2708969cdfd743dc5c14d4070e4d185231b0c5287de6ddbd7ecb7ad72c33629430a4a486c7c63b0df27ffb4aac113a42313ba1688310c220f858827951b53c740b37d8ccb5aeac778316da0b6c8261d1f384d24e688aea7266b6cc5515eaf77889c12ed34dab433361a3ae01a8b63f3b71242510648745d3b59337eac011a5df644241637070dd1da64bd7627afaebef557cffd863ba609aec91f991167c9e7d0adf0cc913617c6900dc1f29c6889965239bc9173a51de6ba64dd09bdd8d47462ab0e243de5622b786b55f8f43c10637b38cc125696d0ea1f6469d8aa8e06be6102a60894369b6a114f3e86d4f271284f2c3bbd7106a0c7dd9412757169e5414487ab8e31338cfe58e64ff1ccc5e04ab5f3fffb5178d38a15f49549f94b8aa743605a2709da2d22c25a0384897b48a23216df05796a40df3b9277ce6d99a8cc7d20b4b00678cfac26646d02bd1deacd3e265256e9a2b70a7bd8f51d26d53b81a43366b3e3e7b22496a44cb89d8a140e41b511dc544e74fda4e8c298b84664aac1bf3ecf191d35a99d4a57b6fc075f023337444a06fa082f3026e6104912bcc6de15b7ff592d9f5a84f4b13d3c86dbb5a0c2acc14286ff30ea8fa4308aebe97e177c8fb76a88308b292fca01f5
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142495);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/09");

  script_cve_id("CVE-2020-3374");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs39776");
  script_xref(name:"CISCO-SA", value:"cisco-sa-uabvman-SYGzt8Bv");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software Authorization Bypass (cisco-sa-uabvman-SYGzt8Bv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-uabvman-SYGzt8Bv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcd6b0a4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs39776");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs39776");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(285);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_vmanage");
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
  { 'min_ver':'0.0',  'fix_ver':'18.4.5' },
  { 'min_ver':'19.2', 'fix_ver':'19.2.2' },
  { 'min_ver':'19.3', 'fix_ver':'20.1.1' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs39776',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
