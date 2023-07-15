#TRUSTED 62e565276fce5d4f7d8e57dff50ce91e18a74e9954aa496a54a09d52fa729075e38f55b9983e4a4d8f6d7906adde75ce44e8aab9dd91f9def409c60274c5fe020f541b4cb80cb01710ace1d1fe487008691c1898744033d857c69162baea4ab6450a837223c3735694d8db2b45deaaf87ddceb3f6c23d2ff8fa9b30f513ab7d311f77f515b22fe1b2b2a924a965bb8ed11da9eac49e9badac895e38f40dbcb14d34ce7809bbfd0e55a26c3328a521e7a894a2511d3bc90492797aaa83c3daea8ba2cf87272359ef73638b2210cb41f27e14fd670c686dd36bb1e845bd177703036a5a224aa244b7dff07c981e91fc6da9d1c4bd84ad691a35ab0a510a07b154e1ea657264113d2682bdd06d4a5c1377d3dee64552d0c90bfc256775ea4e66f90be526284b9d2605f822e41b4932e6e69d86089a8df8dcf14f2fc7aa9d0c2082f187b3fe52dd41ddf961cb3b4cf4f1f0ed9e4c26af77ae70e8bc6170a245b0d26ad7bf1cc3046647ca2548e0bf7dfe7a6d46ef92e83bfd2d5e0d48b8e407b9359ba42fc82c17cb4636239c971c2bdcb5d14bd98124fb1e52874d7a8bd4adf00070df1e0eb4aafe4e3b55d4251a791d339e549901a325fdce2bad229cb31b4235a51f64b2fb3bfee1fe9d28936dca11eb982e5c84602f1f237f814fcc01f22dafd46a167555f5d2f71883b6334fd0e926242b7315859c8cc3166ed800f65bfa54e
#TRUST-RSA-SHA256 4d12b934fa0f28a6a28972428f63bba990f95fe8b17cf2484fbb9071b5a17dd34af565a4aa73415d98d5bb470031e9a3da0e7f6770fae4430c0b4ddc719458f0a5bc5e251bbde5d287cbeab1ad29dc0ac84e5bb81d5d904533e6ec571c63d56c88755e85111dcb4e2a01dce2414958a5f43bbb4412129c16861da1f62cbaa6dd2fde3a088dc86c5253e2fa29c8b3cc13d7ce7382c3ba8a3f361dce1f9078d5942a8a2f1b4f8e9ea932d3054fe63c75210249606d02f14353b85674bfad5614676f51283a3dc4cf2aabf8d7110c44f6f27f994d147510aa2da42535938adf5cb2393e46ebe09c68feb81ab9546cd1604e5a40f61f074e7b4da880dc953f867700b4636bb0e9e021f8bcf53d3fe507e9b7defdde81eeb5f7b9f45c5264c5b391d89c714c168c5347b727b459dfeec168f83ab96f669a37ad64544cf79d6f08b84b4f48647f04be1a26553fcb690f96af5106a59e0d0f3bc43cb4413ad505f2cfac8bc9c559f4975e2ceacfb495824e0cd02d22f917692f1ba02cd4f6bbfe6e87fa8de0b5fad162095208caaf8ccf09b38a2d2455a4d645515395562b25a5c95ef7737750130413036a2df84b5dba95067c26c9e27a42c7592216c715f1558e539a1aa2b6dccd9aa1eef571fe5c7d7a354bd538cef30d39ff8913fe9bb6e4567af40c50b0a3b3db17630e5355e9ed331304b3a24bddd3b596ccf7aae4171ba119cd
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165528);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-20930");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz46392");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-privesc-cli-xkGwmqKu");
  script_xref(name:"IAVA", value:"2022-A-0391");

  script_name(english:"Cisco SD-WAN Software Arbitrary File Corruption (cisco-sa-sdwan-privesc-cli-xkGwmqKu)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to
    overwrite and possibly corrupt files on an affected system. This vulnerability is due to insufficient
    input validation. An attacker could exploit this vulnerability by injecting arbitrary commands that are
    executed as the root user account. A successful exploit could allow the attacker to overwrite arbitrary
    system files, which could result in a denial of service (DoS) condition. (CVE-2022-20930)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-cli-xkGwmqKu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88c0c1a4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz46392");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz46392");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20930");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(88);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.6.2' },
  { 'min_ver' : '20.8', 'fix_ver' : '20.8.1' },
  { 'min_ver' : '20.9', 'fix_ver' : '20.9.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvz46392',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
