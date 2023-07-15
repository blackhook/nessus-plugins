#TRUSTED 78579885c44575bb848082549fe0523ae05bea4967f1f01e852c333fdcecde24f522551a1fb44158da4de752ae48882c63dde7f7098537cd537442018da11793ecb867d3f03640f6b5ce0f68df8e62ebc0de9e40fd02bd2879b0d03f1207f0ed9b63a54b516bd58cfa53b1ede0a4f3ab156b2d29127ca3744e6eb142c220f50e522e66122d60cacb4676cecdd122c74b91d3cce39042a5777c334421f1974e6551f483c285ad21196416b1edd13674441abf92cb42c363ecda4d5dbe165d012f5c732d6c8197c66c5a87f2ac7ab9453a2e01bf5887a309ec35322ee9d49b6440f102e3b80c10b61840925145fa68d97f8077966904b832ef420812ad12607bdc517774c384756528b675e80433519080ba830166b978c0ad9dcce471d52348979759927321d1a114eed69bf45388f217860993e2acdc2ec37063a748db9d911ab74a3434d3c441056a04d0c2e53e9b8f2e4ce037fc19f257b31e7d99690251e6cf9769a12085b90c6445950d2a91dd366b603f25b12982674005b72077700303f42b28381a923ab7b4e972d290391528d46d013a5aef8e8addb212d6dfac9354081dc4f0c29180d621b53e96f9e160b3bba06f7aac49afd10200d9f95a5e36cd3173f716cf606dd7e045558eee473dd77267846c0c9f876a4ebef2147e4fe08050f3333cef85318e0711921075691535cbdafae21b1e92e06fb6c2adddf4bf6b
#TRUST-RSA-SHA256 155ce89de5f8ec9ebc11c9620a90fb43be67ff777ba1a846393d85ceb5a3376d2d234b76c25e281504fa7089357067507e1637372f9bcad82f6e6a66edf2cdd9292c626327c70621eea20412614e02d1028dd34d199f13ead475eac32cf2e192a14fbc5e4af04cbee38760b6d2aec13b752fe97f4841d35c75d4112b9a12916aaf07fd1aa5526f122fb8f5ca78a1d223a1618d56e5cf02494ed2c656d6351806054c1692d076c8b2668736047dabe4d227d515a920e0c0f491a420b714e5e21556b44b4d12a67f4bbab57b165415084c3896a0052930e04d971e7e8bc34c90857519e6191a9581f3501c4788ced65b270a577aba8446c75ae0ea950943918a160a62bf1e7fb8e555bc9736aa3b07463a3b8307531fced21e6134f0acb89070021416ae6db743123af833c2e7f853633d81fe2873bf7319b6f901f10700cbc1e9c7bd2c57458a793dfabe75d7cbf4a7e9dcad7d38179a4b11f327a3b907d7d63bf4c81cd635f2f724643fdc01b2c09692213550c77e007fa78117510c6df664ed9e0ca5595642bf3b8f1821ac11cf7e67fabaca09f1d235cb604f400ffeb79c22d88afa207cdb9bc6b400078bf92c3d76864b4596920b83abdcaeafcd31919ee3433f1d57e4bde64739e031bb8d2a45973c77ac8b81169ca6987697cf8be632175055939fb2100571a7ce46e79e6cf94392356ce25d4b5434f7041c6e093b231e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166912);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/30");

  script_cve_id("CVE-2022-20868");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc12184");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esasmawsa-vulns-YRuSW5mD");
  script_xref(name:"IAVA", value:"2022-A-0463");

  script_name(english:"Cisco Secure Web Appliance Privilege Escalation (cisco-sa-esasmawsa-vulns-YRuSW5mD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Web Appliance is affected by a privilege escalation vulnerability
thathat could allow an authenticated, remote attacker to elevate privileges on an affected system. This vulnerability 
is due to the use of a hard-coded value to encrypt a token that is used for certain API calls. An attacker could exploit
this vulnerability by authenticating to an affected device and sending a crafted HTTP request.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esasmawsa-vulns-YRuSW5mD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38dfc160");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc12184");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwc12185 and CSCwc12186");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20868");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

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
  {'min_ver' : '11.8', 'fix_ver' : '12.5.5'},
  {'min_ver' : '14.0', 'fix_ver' : '14.0.4'},
  {'min_ver' : '14.5', 'fix_ver' : '14.5.1'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwc12184',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
