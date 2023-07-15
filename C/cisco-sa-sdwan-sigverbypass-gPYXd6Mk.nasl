#TRUSTED 1dfe9736e2a810eefffd54fdcb1cfe82e17c4c7e75a73b49fb619044555a4370593f75066d0cb11b31532adc31f3a2a79dd70569d0c17b610f011ccb1b8f34a2c7cfa81386bb495678c94b970a4d8909938200b3d70f6a02f87ff46b834534c8fef99474cd3a4425f4cd0e18e91d504c027c3d2fe98404364a7b34b8ba920b0e12e224191c90b671dd656a7de9e7606c16f76d26f5fe3e9f65a3d77a02be8b28a4727e25f22ab3777fd251a7109f9ca8ac3f1130d18fbafe07c4a160bd281fb51c826fc27610264544fcdbf4e08f34a3d859a37363dabadc000c3852793456a053034b838497777267a98dfe46dc40ca6d0cfa65e44a52abe534b23bf271321d5c509472b4fc2756afc5c5156de6359ecea205438405bfe3e8b9d2766ecb202d843ddb3f571ab8273e1a35d564ebda05708f5b3fff2c32fbedf6166ad7779bc1eef0d7d242157b199ac3590ad57d3c7133fdd5b9bdac1d160305ddbb495828afeb89271b8215dcd6657e1ac17cc94fd90510f234aa1f4d5f951ee4ced6a30d4b26437ddcb294e234c84a737dcbb73b1ea17464fc4a05aee210799546d9ac6b76c1431408676670db7a8ca8323d547e45e231b328e3b5bb8f09a39028f3c6b4b900a15b3e51cd6f376a26d7ac0bc0db1a6122d182346d089a1f03f03df2031e87d74c3cd6bc7cd082609641eb3e571dd51f0583be34859e4a22ef65dedbe89396
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150050);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/28");

  script_cve_id("CVE-2021-1461");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs92954");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-sigverbypass-gPYXd6Mk");
  script_xref(name:"IAVA", value:"2021-A-0118");

  script_name(english:"Cisco SD-WAN Software Signature Verification Bypass (cisco-sa-sdwan-sigverbypass-gPYXd6Mk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability due to improper
verification of digital signatures for patch images. An authenticated, remote attacker with Administrator credentials
can exploit this to install a malicious software patch on an affected device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-sigverbypass-gPYXd6Mk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?306521c6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs92954");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs92954");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1461");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if (tolower(product_info['model']) !~ "vedge|vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '18.4.5' },
  { 'min_ver' : '19.2', 'fix_ver' : '19.2.2' },
  { 'min_ver' : '20.1', 'fix_ver' : '20.1.1' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' }
];

var version_list = make_list(
  '18.4.302.0',
  '18.4.303.0',
  '19.2.097',
  '19.2.099'
);
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvs92954',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
