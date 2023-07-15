#TRUSTED 7f65db43b14340249d074abb0f36297f87a8c64247a9dea88bc56c9efb93cda9339246122271655417b0fca9533002fcd79dc375d54dcd110c971c77bfcebaa66c357291d7ebbb55e559d4c796ebb48db541438067131004e949a9e2f754c4a944ff8326598e60fa165c77c373589ed32b38642c7bf813458914be2b7a3c4354c0ec6e735dcd87ba651d614c42d63de2d7f7a5d24b21586a228d74f25de29132f2fea121a953de46168a7445c21b93e030ba80b0be1cbd2e1074ddc7e06ce598ca3a1e344b085e55e4d2a4450b7fbccde1ec3ad5f6af1105bb244fa9c7435be4a3d9aae1e474bb59e21bbde9b5280ad0d856f92fb62c226e3a17f5c9479d76be6bfefe0a67874ae97483faedc080b33f5fbe6a30ec407fb43fe55f960ebb3b9dc74424141a4ba4f1e8dc7eb7e6863ea9f6cd84bef08c05333dc6c3f5d967490902c8c92c33b9d7f01ab611a145aff7fee6a559f0aa7382b6ee1dca26d6804e387c4c49cd548f93ea3b144e0fd6c7c70c193a2f84aa1149f918a22cde0ad123437992ec5e649963965f3de3161869dd5920c84061d724d967c9d178c5056ea016becce9166b9c602baf20b157374411e8e813ff4f97f0d7b3bd882278b8cb36a54647df6c766d297e2e31c251444bc51d4f924befefb4259284aa26cb0058852847f84e4fa964a06fbde3be6476ee25d07ab0f3b2b4ab30c0d4a2a929d3a2a262
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147758);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/16");

  script_cve_id("CVE-2020-3378");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt66733");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sivm-M8wugR9O");

  script_name(english:"Cisco SD-WAN vManage Software SQLi (cisco-sa-sivm-M8wugR9O)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by an SQL injection (SQLi) vulnerability in
the web-based management interface due to not properly validating user-supplied input. An authenticated, remote
attacker can exploit this, by sending crafted input that includes SQL statements, in order to execute arbitrary SQL
queries.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sivm-M8wugR9O
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f516d394");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt66733");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt66733.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3378");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0.0', 'fix_ver':'18.4.5' },
  { 'min_ver':'19.0', 'fix_ver':'19.2.3' }
];

version_list=make_list(
  '18.4.303',
  '18.4.302'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt66733',
  'sqli'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
