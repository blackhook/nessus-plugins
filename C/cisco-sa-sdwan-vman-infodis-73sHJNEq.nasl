#TRUSTED 31c328877cc5b01f0ad12d5a65901197b9a937924bd7d7d93effe37f814be0996181f645c9ec443dfed10fdb20731bd5b4d4db240fcc6bc048c734d1505f900a954031292c91c43be26d7df7c0875ade076fd3a0156e22785e7adff5af92b28dbe70bd9f8464636593b85b1b5fa01f0966816a6cdc9d720ea77aa01b441179ebd5e21ff401360e1b59596b31923db95d665dd33eedfb9bc9392952d9e82adcf9b540c9882d5387308d9e78df1345baad56ef27e4e31961ba7f3a60c02f6d87c337c254f5a6d49292175c5b4b5d8be95b5312247670f5395d46b967fcbc55be2d6360c3c9fcc100176fc3e45dc3941d96ef77127fc77cf7b47e5dc20cb5db3bc24f4e394ac2775689b83eab75dc223b91ce915dc42aacc14668dad7dd2de72be665e8e3867acc44eb6c6dbd42915fcfc61684899e6fc4c9dbf9983764e05db99f4560cb0422d28867a99abf051d36e4aad377f919faaca9a6537cf217833547070177594a2aa82f97a42c90061b3b083341615881fc216cf836929da7f0ab0c0bb92e4b73e178bde609adf7e4a4eae690672c78b521d1a59e741906bb04f22b326f7cdde4c44decc13bfc365d91bc68d8c1eb7a3004e81ab9b0c836d782ed97e2f9c1c7f84cf8a6b7fd140514948afcac427d4c11ecb128a56ddb47e45198b997f3088f3d861a9e01cceaeaea20bdae15d30f0ab6f81f5c3f40b09e6e60c63d96
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159721);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2022-20747");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy67842");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-vman-infodis-73sHJNEq");

  script_name(english:"Cisco SD-WAN vManage Software Information Disclosure (cisco-sa-sdwan-vman-infodis-73sHJNEq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the History API of Cisco SD-WAN vManage Software could allow an authenticated, remote
    attacker to gain access to sensitive information on an affected system. This vulnerability is due to
    insufficient API authorization checking on the underlying operating system. An attacker could exploit this
    vulnerability by sending a crafted API request to Cisco vManage as a lower-privileged user and gaining
    access to sensitive information that they would not normally be authorized to access. (CVE-2022-20747)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vman-infodis-73sHJNEq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a0a5720");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy67842");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy67842");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20747");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(202);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
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
  { 'min_ver' : '0.0', 'fix_ver' : '20.6.1' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.7.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvy67842',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
