#TRUSTED 79f73df5129efa7ba342a9a01c72fff37aa1221c73562b6f14c6702cdc24b4ef77ba60b1a81459a976419824c76935fb51abd0de01355214b681d44223288704cff4f6c705d13f41fdd4fd4066e6dd6d153533151f3cee340b4a90243efc9435cbae51160b3cc992e9b3eef4c77a557fdc72f39c3c8ee0a5f81987d6a0a4728bf03cee0404efa48dc681d13853b6e184c15e461063b191aab63c93f191e8a4a42cbbc2531fe29c2d4e326e7fbbf137e516e7ed1c01dc9ce11a379291f48e70642e1efe7cab1a257bf2c3b83a58b4c0597796b719f0fe003cadd3e868a54ed378c3fd1be4ee364e030eed051f1677acc0d1296ada4cc7c661fbc8f9bcb2d4fae8c048bbd6ac232461d18908bdd13209ca69d3ebbd77c2fee5a8dcaf7b7b0b49e6fa8a8a3087d08e8143f31db7beb7bba4c445ce5456031e4498e5a8bd9c68d09e184055c515c70ba59dfc16d7eb997aa664d5d030575e39f8a681a7280016e4011f3d41a19162717687cff039d3c3abb0e1f4b65ceedec67ffc2f6fac1932a61d4d1bbf8e323d2f1d9c1943e32d0a14e77fbe0fb98d79bffa7b9487b9f426b509c20d65071302c6379b851d73edfd239777c2f4c509e33dc02e78bee61db802c61859f88ce70a6b787928f0adf00338f96c84bcb61f09c7ddca7822d4bd5358c10ac2a5f0518a0b98b5b8523ac6b22dd04e5e6d1e616dfb299f1b20c1f2e30a6f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141370);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2020-3351");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj14805");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdw-dos-KWOdyHnB");

  script_name(english:"Cisco SD-WAN Solution Software DoS (cisco-sa-sdw-dos-KWOdyHnB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco SD-WAN Solution Software due to improper validation of fields
in Cisco SD-WAN peering messages that are encapsulated in UDP packets. An unauthenticated, remote attacker can exploit
this issue, by sending crafted UDP messages to the targeted system, to cause the process to fail resulting in a DoS
condition that could impact the targeted device and other devices that depend on it.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdw-dos-KWOdyHnB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22451278");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj14805");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3351");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_solution");
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
vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '17.2.7'},
  {'min_ver' : '18.0.0', 'fix_ver' : '18.3.0'}
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj14805',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
