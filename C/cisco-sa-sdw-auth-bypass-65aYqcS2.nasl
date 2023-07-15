#TRUSTED 3d350c43b58f745eaaa31905c0deca06761f914e826670208990d851d028a6bf0e85fc341c04a506811144eb48610d02bb773cccab2d03307dab507c027c566591cb7b120695802b26df64dfd54f630c4018934c63a5fa9c13b7fa4a049966b1ed2f694ee9a3fc83d1c9a8bd5bc3fbdeb8e00d1cef11e8e8cfc4fba03dd3683423b23f9bcfc73f8dccb1f40464e6fb6d32ef8aaa632cb8ad15c9bda2cc1eca7a7609f63f4463d2f69c227d506861c286c1b6e52eb2baf720999cf9f77920a3bb87fec907b951fb0ebf14340282c9d6854a5f28291f872d20062b89c0b0129daf0c666f4ba3baa817edbe032262b866e325e23f2580197ae934fc2d4a361d1dc6e4868dcf83205a20343649eff1715d5d3f852e55d6756d008f717712de2860933ce7cf02ce690af24dac3cfc05727d8aad964f1d2d6ee1a707a2449fb4cd3f69228a0c6f640b687b1cdfd0e297a8870c0beb10b88a6bdd99063b73ab9e52b808e9f4e4e58efe36e6e10d35592fb4c9478541af251c151463228e0dd4dd142372b77749f33378bb91be402ba042508a2298c067e1832420a6564c1ef67955e1a271d9b60cd17692a559427cec8324fb9d6e6ffdc0a2eb95a68a4915af4b31dc79a6c3b4250da162dc881a1ef839fec0019cdbb454dbf7fccf7520385ded2e94b9f81243aa85d62c39b2c6887705396e5778ca0fc4978060d1a6620e84f936f392
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149330);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/17");

  script_cve_id("CVE-2021-1284");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69876");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdw-auth-bypass-65aYqcS2");

  script_name(english:"Cisco SD-WAN vManage Software Authentication Bypass (cisco-sa-sdw-auth-bypass-65aYqcS2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability in the web-based
messaging service interface. An unauthenticated, adjacent attacker can exploit this, by sending crafted HTTP requests,
to gain unauthenticated read and write access to the affected vManage system.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdw-auth-bypass-65aYqcS2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80f54587");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69876");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi69876.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1284");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
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

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvi69876',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
