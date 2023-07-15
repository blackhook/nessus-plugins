#TRUSTED 4095ac8967fddb1fce7e328682d595a58a57320ee3d801506302dc9b34abd33b75569c478f353bacd20b49dcafbf4ad2c90748cb72ac37614f1cecd6c43274d1d4adbfb629ad9f321c5ef7423de192f323353eda435ba4394da07f86a08f8cdffc1c363be118b141e1e45d6c4dd8fa4e863e208fa5d84814f9ba723303c566c576d71d94865c58350abd65b9741dcae494207c7ff4d2d1f22177ea5e4c82b85e55cddabce1db11cd56592f017fb84aae0d312b69f237169fc1f5999984cf543e3122f16e9081deea9eb912ba5b3adb4e60233d6c2d69f8c88e71fe26d136abb0f4453aa71843a5334f88df2f28ecfba710baee4460805db53b81e22dc2203fd7881cd49b4fa6415841b2722b47ea24b6b58cbfc85a8dae7b56c2ea277b6cf35fde13f8a3166b4f5fdc0888298f1c41092eb8e7eb0a036a127d429bffeca118095a3d34c1934bf247c9efab2167c1aff998239ce945a2810e4706ccd979a9c5b6821445c41cddf478218d3207b2a1871824dfb11e1cdf048c261ffe265354755fe858727fe43dbb754fb384a3e4c4aa7be978f4b4c78812bacd3e4c5e794484b7b11e48bcc87b1615d72a7a97f2eac4e069dd14d78100cbcfbce1cb7b002e24014ecc6ef5588773996ea1b6a9149d13670b7af30984fd7108d0150b06102f7f29a7be99d9395a79b0039f76588b8132b9e56359dcbf2210f2ba599238708da3a1
#TRUST-RSA-SHA256 95d146fee38caa0335532cea7f87a6ad03ea3f867d9c22c29a22b8c8bb51e0632b48f827f60a7af1a0310548b6583589d4399250812412597ae1dd03e1fc48ec4df59fcbb34c4d82a5d207c3fcef5a1024d927f7f5a3287aaa7a8d6846054333b66bb0927a525e5461af8ac573033408710325cd00cb46c39ba8433564e1c460fc3012ee3f500c34002c1f75762eef204b0df4a479c633a2fec66bc6f974571e5de097d6a1fd83cc7064d45090c7bd0c4f628de983ec221a6337f1393253e1f6462d3c31aaf0bd953bac09c02cba30bb31b59aca80f941b111ef3fbbb986a0b34cce9245a1a535a8cdeb6e4cd66474acedb27d188203e4272a6eb4f1993b4b4c9b9ced1a5fb107ddb84b0cf0b50328f1b7425ed63ab08104e3ebdb5a75a2c56b251ea5a0f1d8627ad1bc87572b83ffe1c128056811750768db45c90b20f2590340ffa68531f525b02a8825735c34f738f4235242828865cd6f18dc6b7b89304728af1f531d929a0c9e531670e8ea7a6d319f58c81c24d7a2a3c4ddcf37953fa96bcfc5d31dd1aff1df44f0134a3981103d78439b617b1c1f25f952545a418f7ae49d29e923ce41487a3758116f2bee763e9ec64526f197125ba0fefd8fcbe614b48570e2d1b0526cff97361f035e29c692af84b0ae01dffdc6edcf63d5c87058ad86157fc8caee77271ca9daeab14c79d6d8dfacb7c7b2fd62fb36c40c621cef
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166918);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/07");

  script_cve_id("CVE-2022-20960");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc35162");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-dos-gdghHmbV");
  script_xref(name:"IAVA", value:"2022-A-0463");

  script_name(english:"Cisco Email Security Appliance DoS (cisco-sa-esa-dos-gdghHmbV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance is affected by a
denial of service vulnerability. This vulnerability is due to improper handling of certain TLS connections that 
are processed by an affected device. An attacker could exploit this vulnerability by establishing a large number of 
concurrent TLS connections to an affected device. A successful exploit could allow the attacker to cause the device 
to drop new TLS email messages that come from the associated email servers.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-dos-gdghHmbV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49ceb9f4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc35162");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc35162");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20960");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [
  {'min_ver' : '12.5', 'fix_ver' : '14.2.1.015'},
  {'min_ver' : '14.3', 'fix_ver' : '14.3.0.020'}, 
]; 

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwc35162',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
