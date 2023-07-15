#TRUSTED 5bd4a9722bf222adbf5bbb3dfdaff916c8a01473caf386fb6186d9fb35dc2dc1fee0f78d20c4722a42e517bbfbebcd65f09363973b7bb00c350345d87df9577cf463612025a615036d23773ed8bd347a7dc9a7f0a1a50162e28fd5e601e0988b1fdd85b2113a65da4195dd800b5f71749646e5e8c3d37bbed7aa15086c74eed06f684eba939a2d8c3dc722f3422c92b8ae80de350c2d39fb869019942c81b0a709d4d4009c123684affb11c0ecfb12a24af51d23323c5daf243ae6a5a4dfc35c73f8586eedf745344368541bd30128af338f434c2f4c625568a3f99a2c84fdc3947776960e954cfc73edd4e28d6143a7b1dde9e4d710371411f4445b12fa72c2084e8ea94ad2f93fc069ed789aab1893bf89962c12656ca4d4d36b5cd826f5fb1e30ec97d5170af80cad7b36b1e15ea9a2f6a753c890890e93daf232e8e9e53af36a8a558e35e5adadda8c10beb814bc8e8ce87b1527ba62078cd1ecbb8175f9b8c318466281b4c0da2fd79362cf7875bc1acc9f7b6017c7447d0804a2df38a038d3dee205a993e77b621b79a5a6198d61a1e31e9e1dcf19d18f5656a486656ddea9ce173079ec2f73c42632b9c52ad1f7ae4591309dcd639e511575046badb72878ec71faf132773bf349e0cafefb16dcdc7f7fc9655e83c703fdf9a8c708739a5f4f4d846ddabe7cbc0a42061a4f53f97ecacf94c07958dd0ec4ccfba6278e
#TRUST-RSA-SHA256 00e5cde9918deafe82e07ed7a4ece9c38e5d53aab506816af5a83323144c54c1ec9f3d93b4a50635d8dcd81616192f36573e7f824e27162cb6873f5861f204b64bc277c43d2081b90c78081709648254cccb2a2a5ee2d12fe7a10c4fded048b79cf1665c4186d8b7607a4e4405b08769eab36161a1955caefbf4ad9a60f79e7bb43b67b9a4428f6650fe14fff73c9b430cbb9824a732e42a8d64589929790c2b43df20a190913240dcb8124d850a0cf46a5ecbccd3d0e7e1339c907882cb699129406ee1d6f53fc31d72e9e431c79433ff078cd03804e66ac246d793c838c79cc95d74f367e7ad6ca09226133c16602c82c531c08e80be3f8613279068f793cff167027630752d3b7b63d04a613c1701616d3309e46d916c33e8f497a4e70682344b82b3585f3f8111671fd868fa4eabc08da65611809b65a8c33206e18e337621e479af94f7d3f5d9c6cd06dc0ac5b1910241f422c9839004db20789b1e10d3025bd20073e28fac494f103fec815ba39ba1e706432bf94e3f217bbd4fa435dd97ad9d14cb1c5ee3df1f3ea2a6cdfa4d7a66623f10ef02b51a3492c5c674ba6e9b3d9945c05e77869ccb4610ab862f792ddaed2b4a178f04a556cfd9595607f6974ecd1874c3c42bea0b02dfc39e49d63620630685f720a06c4315c75b42f42460e14b91bcd7d53ea7bfe10b7e23eb75d71365db96d3bf9d4ae06ab828460307
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148954);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-1491");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv03493");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-info-disclos-gGvm9Mfu");
  script_xref(name:"IAVA", value:"2021-A-0188-S");

  script_name(english:"Cisco SD-WAN vManage Software Information Disclosure (cisco-sa-vmanage-info-disclos-gGvm9Mfu)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-info-disclos-gGvm9Mfu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36ea7178");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv03493");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv03493");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1491");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.5.1' }
];

 
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvv03493',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
