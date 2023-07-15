#TRUSTED 169d9b50c5576e860da83843614220d6b73cc77fd1dede20c194357fce55e00f116130de32298ccd5f2e36644037ac452e83b665c5629d1379e0ffbad57af720ffb3bdf1998ff5dfee65f093fe8f43b462802e35383c81d752b39a7ae49890db6881b81506e54f2d99b7a8d8fda9d57b51d5a8bc3cda7bd4adbdb9b1c8b15c54c0286a29611a2417dfc13611aa5aced2efaa1ee5e4902a137c3390bef2d0d3140927c5af717fcf478c673781a66943fb9f27cc8184188adfdf038fc3161022b89e9eff6e7bb49612a35ca3c3df354bce95b18cc21af3737a430f52ea44f1b19d16d011b0533483af0af54b4dc4adc1379cc815a07101bfc2c0e7637e8f3f827556535d38470d585f63b21168e3ddc21357cf78fef4398f6e78ceb765570b318dcaeb4f34fd7fe3cb27843c60af96c236bba23fd126dcb164d0bc844143a297ed765eca34c28c427301b3dc540e299b8d0c730fdea0ac4032433be0d08d4aa324f254e5ba5cf820bc8489c150f685165c47553ba0d417ef1652eaa68d9c61ac0971fc885f97c4ee7bd9cb3bd332d1aa018ebb3a584bbfb91ee3205de23d948bda7d042f24ed428494fe6c2023d9c178d41f047169402d83069906908a0940aa048acf3465536e94bdd38e8b897a96fe7b409d9eb7f1bc7f6227c3a3842ecb17629436caf4814c98ec10220b4e141cc94feec49e5cda56472a664411d9354de103
#TRUST-RSA-SHA256 0f3a813fa3655e6d73e479cd628c92cf8d14c251c501d6aac142854c34e8f07762d0c21655cddbbb2cffc8ece6ba80804a15d578f5eeaa35ee658bea7861ed7afd51bd2a876f9d4fb2e509b163dbced34fa32802a5ab3bd1afff87c8b08bf4bc06005609d600fbbc5d55da17c2e35343b7af724b8e89b0460cf21cfe709f0761e5afc2ef65fb417dda2226c77c7d70de0b0dbb463ec87fc4ec739b6b2ca6fe2a7f727f15d5732ba8e93b5954a6e8da3de6a10ed68119644f9812ce65a00554a2b651f07230d1c491ee3038d0deb33402be827a077acb9cf4d1fb184bb8fc3bf3064c06e1e04b71586bd309df8bb7b1a676b3758ef67431a87c444b5250969d8076838d661aa188d9ebc084ba11e8ad2961184f2966bd7089065e2798689dbb58d100659967e27bdf90a2408c5ddeae948bc883740cba2b2ac4194d2044410c48b669e2804633b722ad36dc3610319bbeca81d781577bc66305fd2212736c3c0d6c3a27d87918eb392253abf685a84403df314bbdbeba467f1279f488dcca3c24ef46fcb23d50e56012012afc08af5f49d076035541f99340fbd4d306d1d04a8601599725003a71b4196a1354dff250dd40e43d5eb4c992c37db033fc1e108f792cb7a79e4db9270bd88c2c03353757f88a7e2420ae48399c3d824147ee0ce028f8a9da59957dec9ce5b0280c16324441a65dae969134dacef491a2eb62ac3055
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165529);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-20844");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz97362");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdavc-ZA5fpXX2");

  script_name(english:"Cisco Software-Defined Application Visibility and Control on Cisco vManage Static Username and Password (cisco-sa-sdavc-ZA5fpXX2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in authentication mechanism of Cisco Software-Defined Application Visibility and Control
    (SD-AVC) on Cisco vManage could allow an unauthenticated, remote attacker to access the GUI of Cisco SD-
    AVC using a default static username and password combination. This vulnerability exists because the GUI is
    accessible on self-managed cloud installations or local server installations of Cisco vManage. An attacker
    could exploit this vulnerability by accessing the exposed GUI of Cisco SD-AVC. A successful exploit could
    allow the attacker to view managed device names, SD-AVC logs, and SD-AVC DNS server IP addresses.
    (CVE-2022-20844)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdavc-ZA5fpXX2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd59e682");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz97362");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz97362");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20844");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(798);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
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

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '20.3.4.120.3.4.220.3.5', 'fix_ver' : '20.6.3' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.7.2' },
  { 'min_ver' : '20.8', 'fix_ver' : '20.8.1' },
  { 'min_ver' : '20.9', 'fix_ver' : '20.9.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvz97362',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
