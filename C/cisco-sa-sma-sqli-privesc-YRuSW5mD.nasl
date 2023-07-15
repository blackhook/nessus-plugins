#TRUSTED 6909677fb1c83f932983526bcc56d3fed72599e5cb2220e4f66c726b52a389d91949628dbb4e6a22e23674960ad1b73f5526371804696c4469e4874b8b62fe63b85888993f3f8cdcee21488dade9e794392a802baf88dbe1c29de89a3ec0179c285306e59484134f5a2c18c52fb1f8f63bf2bc56a42b0e9e471c117e0c8dd609284f5bb86af1129d19e381efa228e43722a654408310a634168b1994ab69a7879881bd187da3523a06e6fedef427c645fdea693e0a979756ac201c429a124e5a49bcd2260fc0c0e153969720019e2f6d3d7ffb5758bb35e8993e77efbfcde710736b1cde22302b30621200713714392a1cad1a990257bc31cb384669d110c85c3f038ac9589f680e97143e399c423027e4d9d0c3014996ad32eef84944f26304efe1fa8e853430324fa166db094d7c3ffecdaf65341770416e5c739c5ffa81d0dda15fc85faf1af263b79534fb294e432012e734edb06782fccdf2feeb52e866cd8199e0d384db8855fd8d39ad8c59830a12ddfca23f142642402871e44e6196bcd29b92d089c9fb358faf72f159364499fb062a94b5fa1888172213888f2f6150e0daa1546cb269dc5b518dd560a16a2a5bd6ab4d6cd5224dd4f562de55b4a9fdefa8fcfcd0b108b5968e062c5a0083b2ddb0ab3503c515ba4d5cbde0fe4cff4803a6d3b53ee8ae20a060997ee08c8a5ceb66538ed19e21899b43f255f6c81e
#TRUST-RSA-SHA256 7ff05bf5a3d62b7a574dad296998082ec41ca3a31ccc5715e9b29f5f020227588f3275c03d8423ead6a8acbe0dafd1a4b67f76f7142a15aad89dcfddde902da34d8921833366487970c503f442a4a44b6084294573e2942c5917e8a21ba38d8629e1118330b6c4791ff47da58701419904a29fdb2ca0436e1fd55043916f4714a55d51387d3cd601305ceecbcbb7321da3f0ff31e357896da5a84139a645b7e2df041fada5c5cc311e81bcdcd3184d43ad1d14065961f58347cea64c548286ec66745855deb6e29be6de95f045543d3c4c18660bd9febc55d605b811286df85645ef858085c444e35b03003bcba7a6bbad2d67529dc770809064f3baefe456f5aaf3fd057194170267950210da017f599b8e6244a6eaa817c44b7952448e2395758c80bacadb9306e66f381767fa1621d369edfad21c386bd784ce9d6c797bf6871b87231229c02acf0a6accf07573e7958056d32b5837696b58f86b1331ebafe78c26cd33ce1d12a94f054fbcfcdaa943fb5e31466f944ce8ff55798f25efb205f6535ea368410d6fda5de1c134d6208a43cfacede2c4fcf6e4dd59e3d385d3fec78ca3d254c152791c071855b2b9383976a58c8b01a0a07d0fc6c10cb3ce8053ae834cec194e60a55b985b55e17d9d2f57f4188f3dbeeade662961e6d2068c34d3d2d4ebc35c44188022fff36ca24cc364c0cc92922540b152b8b7816b3097
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166913);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2022-20867", "CVE-2022-20868");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc12183");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc12186");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esasmawsa-vulns-YRuSW5mD");
  script_xref(name:"IAVA", value:"2022-A-0463");

  script_name(english:"Cisco Secure Email and Web Manager Multiple Vulnerabilities (cisco-sa-esasmawsa-vulns-YRuSW5mD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email and Web Manager is affected by multiple vulnerabilities. 

- an SQL injection vulnerability that could allow an authenticated, remote attacker to conduct SQL injection attacks 
  as root on an affected system. To exploit this vulnerability, an attacker would need to have the credentials of a 
  high-privileged user account. (CVE-2022-20867)

- a privilege escalation vulnerability that could allow an authenticated, remote attacker to elevate privileges 
  on an affected system. This vulnerability is due to the use of a hard-coded value to encrypt a token that is used 
  for certain API calls. An attacker could exploit this vulnerability by authenticating to an affected device and 
  sending a crafted HTTP request. (CVE-2022-20868)  

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esasmawsa-vulns-YRuSW5mD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38dfc160");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc12183");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc12183 and CSCwc12186");
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
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:secure_email_and_web_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

var vuln_ranges = [
  {'min_ver' : '12.0', 'fix_ver' : '14.2.0.217'},
  {'min_ver' : '14.3', 'fix_ver' : '14.3.0.1151'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'flags'         , {'sqli':TRUE},
  'bug_id'        , 'CSCwc12183, CSCwc12186',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
