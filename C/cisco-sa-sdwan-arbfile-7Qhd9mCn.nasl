#TRUSTED 0ad39e3912acbcbb0fc0147f3466300642cd5f0ba34220a9e01dc38f4904df0fe78fde7e3740d8339426f5a639bcd14cf8bfc613e350403562f37fd56740ec0ac7140c17e03ef53a7027bd12aeb827a986704b4f1a067167baa8457ca373180518693b8920432b621480e9dee891490d2a7acf57f83965a30123a292eee18a45d242b1d15ccc6afe54b4748a7fdc943250cc15954379fba592bbfb93f39ab0020d957046449ee2e96a76155bf3a9d9eb2a53d5cb81c0c4e92b979e694d4b922e732d16051844c39f7122a4b8c787becfa64b58f52429d3ee7144eee84ac10ac3975d06fb8aba97e2c4825301c4d07e239a50c171b461cbafa97c5abf98aabb15297e2fb5b0e8022e3d2437cfa72e4f0a7b599f7496fa59d010d59e8e9f323432566392009b205a95353f1b9568b9fc7614d35fd7aaac5352553d0a63da1609584eae7943181f0d17ef8f475d1dda836ae335499100d08bfd3e33bb6d74aaa693fcd862acfca4d95df7e5b8eae8bbb88f5137d6f095dee41dc1b057926a6af0eefee072e77fbfd7c76716aea5c556e13d7b1dc42556db83029c31ceaf6a70aec9634f88e849f9c3e2a13146bd4b3efa11a417293c226011c80157816641d2a0c2d8c6b5526afa40f9e9cd78ae8fe6b8b78efd9eb123edf426871865196bd005472e8d25a671ede13256eb1ffe9dd41ddf4fb9378fa46abe6bcbcfc5f0fe5055f3
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149364);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/17");

  script_cve_id("CVE-2021-1512");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs98457");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-arbfile-7Qhd9mCn");

  script_name(english:"Cisco SD-WAN Software Arbitrary File Corruption (cisco-sa-sdwan-arbfile-7Qhd9mCn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by an arbitrary file corruption
vulnerability. A vulnerability in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to
overwrite arbitrary files in the underlying file system of an affected system. This vulnerability is due to insufficient
validation of the user-supplied input parameters of a specific CLI command. An attacker could exploit this vulnerability
by issuing that command with specific parameters. A successful exploit could allow the attacker to overwrite the content
in any arbitrary files that reside on the underlying host file system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfile-7Qhd9mCn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5e090cf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs98457");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs98457");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1512");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(552);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vedge cloud|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '18.4.6' },
  { 'min_ver' : '19.2', 'fix_ver' : '19.2.3' },
  { 'min_ver' : '20.1', 'fix_ver' : '20.1.2' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

var version_list = make_list(
  '18.4.302.0',
  '18.4.303.0',
  '19.2.097',
  '19.2.099',
  '20.1.12.0'
);

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvs98457',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);

