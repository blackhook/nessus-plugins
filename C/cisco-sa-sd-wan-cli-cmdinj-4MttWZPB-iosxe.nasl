##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164375);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-20655");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm76596");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq21764");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq22323");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58164");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58168");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58183");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58204");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58224");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq58226");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz49669");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cli-cmdinj-4MttWZPB");

  script_name(english:"Cisco SD-WAN Software Multiple Products CLI Command Injection (cisco-sa-cli-cmdinj-4MttWZPB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Software is affected by multiple vulnerabilities.
  
  Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cli-cmdinj-4MttWZPB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e56d38ec");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm76596");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq21764");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq22323");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58164");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58168");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58183");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58204");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58224");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq58226");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz49669");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvm76596, CSCvq21764, CSCvq22323, CSCvq58164,
  CSCvq58168, CSCvq58183, CSCvq58204, CSCvq58224, CSCvq58226, CSCvz49669");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20655");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}
  
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver':'0',    'fix_ver':'18.4.4' },
  { 'min_ver':'19.2', 'fix_ver':'19.2.1' },
  { 'min_ver':'20.1', 'fix_ver':'20.1.1' }
];

# 18.4.302 and 18.4.303 appear to be between 18.4.3 and 18.4.4
# 19.2.097 and 19.2.099 appear to be between 19.2.0 and 19.2.1
var version_list=make_list(
  '18.4.302',
  '18.4.303',
  '19.2.097',
  '19.2.099'
);

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvm76596, CSCvq21764, CSCvq22323, CSCvq58164, CSCvq58168, CSCvq58183, CSCvq58204, CSCvq58224, CSCvq58226, CSCvz49669',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
  );
  
cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
  );
  