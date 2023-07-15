#TRUSTED 7c0d37a2531879862b1a8ea0ac71cf9f4c1a91b895f7212dcdd76fefd196609a4676db5565ba80da402b7e08fe98abff2e3be657ada7610aeaabd19685566c6d5a90a43466d16ed10b7dbf3ddcd70b112b75202873ba639062418ef2b2819367b053bd51c079c4546ded80465e6e741bd0d1295a066d68ee12a6ca0b120b104b17193a24b83987d61a25e57ca61d4778bacb50f80d7d48117822e289a02132459004d59b9bfd4090c75125a90302967981ec90b4a16ed5db3a86808077ce197536e5b870a4f82a33007509dd98d4dbd148509c75e81e6f530de0389022e0e60a2a4fcef349eb1d7e55ce5ad2d07882109f2fe6156805f64cb981865370d1598a237aecca4309dc8740d8fcb7a9bf1028c0b7f30047eae1ea0edbc35543fa490b1a7e4a6ec7feef3b0afaa642dc8840870c367cce3f02e4bf0d82a0997a937fdc3d55f88faa25549022d3c7195e5492f40221784146a16d925a63555d164b5e5a2ef79bb30930c081eaae06814a39e4cd36a344a1e78cef1ac72c80284a07a28df5c447efcfe4312171b7ebf1febb5c30a8c4de8d7574e1f15e1b259694b08c99142b62c786fbbe33d74fbff8f6c36f48c6eacd70bb0f49273a66d11d54eb7d9b127c471ef0ab7299d618377940b87b955156d8f85c6e5cfa16cb4d3e39bcacd4a19e0ebe6e0c27e8605a26260a15b2742e917a0e8635fe6ab752021657ef4239
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159722);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/13");

  script_cve_id("CVE-2022-20739");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11537");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-privesc-vman-tEJFpBSL");
  script_xref(name:"IAVA", value:"2022-A-0158-S");

  script_name(english:"Cisco SD-WAN vManage Software Privilege Escalation (cisco-sa-sdwan-privesc-vman-tEJFpBSL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco SD-WAN vManage Software could allow an authenticated, local attacker
    to execute arbitrary commands on the underlying operating system as the root user. The attacker must be
    authenticated on the affected system as a low-privileged user to exploit this vulnerability. This
    vulnerability exists because a file leveraged by a root user is executed when a low-privileged user runs
    specific commands on an affected system. An attacker could exploit this vulnerability by injecting
    arbitrary commands to a specific file as a lower-privileged user and then waiting until an admin user
    executes specific commands. The commands would then be executed on the device by the root user. A
    successful exploit could allow the attacker to escalate their privileges on the affected system from a
    low-privileged user to the root user. (CVE-2022-20739)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-vman-tEJFpBSL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30e783f4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11537");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt11537");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20739");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '18.4.6' },
  { 'min_ver' : '19.2', 'fix_ver' : '19.2.3' },
  { 'min_ver' : '20.1', 'fix_ver' : '20.1.2' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' },
  { 'min_ver' : '20.6', 'fix_ver' : '20.6.1' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.7.1' }
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
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvt11537',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
