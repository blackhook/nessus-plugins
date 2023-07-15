#TRUSTED 0b3e9283aac5fc45780050511d15827cdba2f6f8a8090df609625f974b05f85196da1cc1ae6d9f57c24ad9c14f1c0fdd555ed86dc114bedd90e7c0f88700a1ef54933610866da450e25391a46291d6fd34baf2146ffbe22d4f31ab55633354956f31c2a6e8447e8ae3f25e579e5a29e2d809809bbfda19831c89eaf88c9767a68877f3a31bd50716c23ac02888391d1b16983532690bcdb7ce6e7dd7cb26c4461c5ae10b7065bcb122d70e408c1865fecdb8c49948d56a83b9133fff3e3aa56cbfefe1cb7e9bd52a5fdd2def6de79160ee0d04591565acefdb09c7799c2c33e99edfea84dcefd0ae8368958a76d59e4af93f7a634dcb77e41d0c389488f314e2afd3acefe083080d50efa376f327af88c16575735576ea95ab0f665faebe5cbbe2357ac5c75c1a329cc403b933414f6fedd84a645ddf0606278bcc18a6afaa60c049cdf1d1abb8ecee2d630842c555d91f2ac3cdb4cdf8ce67d7cb59affdf16a2273bb52a4a14fe01d31375acbdddf5c8d30c2f72bbff22ae6e73c230646b49a0bcc1adbadd426891c8180bc2bd48c1a280f66345e42aa2b7a91636289a2f6740ec7f0287e2efe5b94d161dd1ba23e7d1a31a85ab07459acc201a7e2c0e09e9aedb75c691e474662e8f456a6be5817078c2e6ebb6a30f499a8208402693f7ee1598ca02d4c7c93cefd444d9bc9d6a5a60f5b228ea8ebc517b29808e6f7a43220
#TRUST-RSA-SHA256 2d3958ec76cd28330d7a1c38d6879c16ae386067d5ae83c71cf0789c7cfdb7196b36f0756391b84ef39cf7c5d1070033327bdc6b9c7c1b3c112ac006c339cdf3b732fd85a7f686627980733266976b21843bdbabf87ff2449f90112ad27a34bea4569cb79827b5f543d71ff1e94c87ab99a465e5c9a37787fb6e13ea2bce9256e78670049a6fe89455af71ac3a2341d38cbe064e3f593ba22ac5207193ef4429c5a695c8cea2ef53e26e1f350b8273110347be7b4b7dc2c1d230fa8025daf4c72bf6d91f69d9a3f82e190f2625b64deb9ae3b4844296e3f0c93a031b64206fc6a1a7cdf5cfd71c9e765db92951b13b001f9d805e1d29d120faae6da89b18a557d11912d190821c35aa6811fa418cd3af9b7e2f01c03574f457060d122cdb579362b82f76c9b45019520c3b9435055a8e6ab12ff247ab656f8926c39455e9cec4c8204beaeb66127295061c61561c04ab4efdfc7c6cd9b51894279b2072824c0b9627bfada0f0d7773da871539f8639fb0cbfec0bd474e4bbf045fbc745be9cd0b5676627296e45f7cd9bb36aef57e7efc58e8f4ff2953793b4a193fab710be8c9ee168f1e415d2a0907fe25730b9ab72dc8fcb14bbb3fe51e12f73721f18a2d9aac0219e921838bd4f805b5edefb6069b2942962506968e101afeab18ba33396224088431573c9d65ff4729fda2ad2fdbb185183e65a7d2bc482adac9992bbb6
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164290);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/08");

  script_cve_id("CVE-2022-20871");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb92675");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wsa-prv-esc-8PdRU8t8");
  script_xref(name:"IAVA", value:"2022-A-0334-S");

  script_name(english:"Cisco Secure Web Appliance < 14.5.0-537 Privilege Escalation (cisco-sa-wsa-prv-esc-8PdRU8t8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance (WSA) is affected by a privilege escalation 
vulnerability. This vulnerability is due to insufficient validation of user-supplied input for the web interface. An 
authenticated, remote attacker could exploit this vulnerability to elevate to root privileges by authenticating to the
system and sending a crafted HTTP packet to the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
 number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wsa-prv-esc-8PdRU8t8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46b72955");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb92675");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb92675");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20871");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

var vuln_ranges = [
  { 'min_ver' : '12.5', 'fix_ver' : '12.5.5.004'},
  { 'min_ver' : '14.0', 'fix_ver' : '14.0.3.014'},
  { 'min_ver' : '14.5', 'fix_ver' : '14.5.0.537'}
];

var fixed;
if (product_info['version'] =~ "^14\.5(\.|$)")
  fixed = '14.5.0-537';
else if (product_info['version'] =~ "14\.0(\.|$)")
  fixed = '14.0.3-014';
else if (product_info['version'] =~ "12\.5(\.|$)")
  fixed = '12.5.5-004';

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwb92675',
  'disable_caveat', TRUE,
  'fix'           , fixed

);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
