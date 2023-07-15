#TRUSTED 1c70ea7e6024b335b78b312dc8b9fbd6fd9b0a919ac226dbe2ed0e5356ac95267cc50a65ce242a005ed152892b473c9643c9522d3884150b9a654fc40cd3b0d2408bee40c5b6963d1a6cae14214d0ce50f613a89b7be37fed99773687a00d5c0536fc68b575e76e7479ea6c8f59445cdc165df7ba9e453a002d35732e7418eecf4cc156371df498d55fbfbdc1b372bb23e3065d381d99a70000e7eca1bdb118bf42fead2f4ba861b5dfe6e7f245d4b34af3f33eeb754a521b8332c9261f5cadddb5a47221d7804227c15252807975151f707bb70fe67b139828c6bbb0ebc88fc61b946e1bfc947dfda289622e1e4735ff7bf24e6151355ad9baf73bf108239cd50a916e1bd9f76ad8941f9239802285875f6f240f332fb9224818e5869f9467158b499428767ddfbdf0b982a4b804d3d4a55d9e0940d046630990fc06e2aedeb59466ce130e30713913d6432e7d035a2ecde5f4d8b08e16d097d1026409b37d4663ab17cece2dd3233665763bc5ca45616612494ce31d5ea5c0929ce468defd9a6cb9a4ad68c0c2a81b72ecb5d3efbb623702aba332a86c90fd1dd9ee6f294ac55a43bbaae28b8623192ea120e1cf3cdb1d0eda0f3a3b0b68403f3e02960a90f81d226b98a8e23a6788c5db81d5ad0faf06afc153f477f4e0b018aa0a147c4aafccdb99613da4f3425f8da357dbdc0a215512caf68fe94153281539360050711
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153556);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-1546");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx79335");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-Fhqh8pKX");
  script_xref(name:"IAVA", value:"2021-A-0435");

  script_name(english:"Cisco SD-WAN Software Information Disclosure (cisco-sa-sd-wan-Fhqh8pKX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to access
    sensitive information. This vulnerability is due to improper protections on file access through the CLI.
    An attacker could exploit this vulnerability by running a CLI command that targets an arbitrary file on
    the local system. A successful exploit could allow the attacker to return portions of an arbitrary file,
    possibly resulting in the disclosure of sensitive information. (CVE-2021-1546)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-Fhqh8pKX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c5ac04e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx79335");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx79335");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1546");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(209);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vedge cloud|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '18.4', 'fix_ver' : '20.4.2' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.2' },
  { 'min_ver' : '20.6', 'fix_ver' : '20.6.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvx79335',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
