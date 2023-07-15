#TRUSTED 076735d50d990082cc49183b708d14405a437cd3d2cdd3adca4707f011f5f689db4ea1e97f7256aee971d66a7115280b7ed37f2e17f259a6724658781afce602a8df78f697d6937ed7391e63ba8d85b8567a0998bfbca5c7b542b3e62df1cbab9e33b6b80898d9a190ea4bc291058388c0bbd7165ebbea4b289ccdcd3c4e526624f8e5007bb59309995dc8edef3a0b2a279648a70b8dcb2683c63e298385de7da506000cd855e4d3ff55aada52bf22be74fbce60219ed0f9de0ae5259b0d8fe93178dfdb25541dda40b9c592122c09bc4517cae1090da12d3d9c2470fb06a6ffbe07f0e6f7a82d3b58b5d4c57a3fbb5bda2bc5423adca11d843cdeea1be38b5387161fce476b2cc074bf157b9db97dc7c6714454f78c67ed676a1e25e3f37615bebfadba5ba92c4cad5d47c7598ac81dad69a6f86eb103b2fc5826262edd14dfa62e6d647636bdf702d439e6d1767c44a71a2a7d8dbb1380c34401b2aea0a2a742011acabd6bf28f5928badbfc74025a6f783f1694dc14be3bd12fb153861d4fae3868e74340538d3d0b92df16a2a7d3f7ffe6a454c0c0e1031264824f8397d9ad97e2246f341aa1b5a1eee4a80f165c67b39b3c2b8072296b0f9090b68d795c14b435cc3289a9e2778f114c26c1eac220dad12f17c6f4cbc097a5992ffda2b0e05bc845df37dbaa6d5c9841e04269082bb610e865d90a5f0baec717e2fcdcee
#TRUST-RSA-SHA256 36184830ecef1c5f7a750aab2c0413851a2d3fd470f60c196d0d5bde67c000641356d8f2632fc10965922a7a77a96e2276e567915a3c070269adbf15dadd2abb0a276ee8b44e75804482ca0655e4e6780eccc89ae74eeeeb785cf530ccb68f8a0425b62995be2bf9c5cc77471c77716adbc70f0ea2d833a629ec25cb80bdd34d391be3ac62d99e44c9191ab44c12f3ad7dd6dedce9ac5a15c9bcb64f52957f7127bf34dd892edfbbedef9019f42626422e088b8014ed46c54621674286aa739ee8e0dc52a3eeffe4b8edbc866e0cb3ed5788deafa138d1db24787fc578659832dec4aae6100e21f55e2df6c6294784e0761e1f4977c09e2d7cab7a35410ffe7fb946aa743f9cd5b941c8fae971862b20fbe5a65f4086e2ff0eefb74ee53f22b52e03d9f61b2cbb54244fbccf8b5e074df93888c33285dbfe3dc04515cb2dedc2b06596264105dcf5db470ba5a726542a4d070249d798f0c742aa62341cc26e65235d5ee18bef8025f4c6cfe220cd525fb5bd61ced3c84712d6631450ef939a9f387c1cff99725c639dd3443246e28bc357c54a8d27d9689c5d44048eceb889fcec9d924c4389ef2e34c3d5fb02b3eb4fd56a79667af0310cb4c6772d0a43de11de7cc6ac6c7d70cb96f6e9bcf407837cac755bede52295ab4c05e61482292c906f31d3b4a3b45ecf0285d671dc6c3678570ed47e8ca950d83dceef988860407c
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164823);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-20696");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx87376");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-msg-serv-AqTup7vs");
  script_xref(name:"IAVA", value:"2022-A-0352");

  script_name(english:"Cisco SD-WAN vManage Software Unauthenticated Access to Messaging Services (cisco-sa-vmanage-msg-serv-AqTup7vs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the binding configuration of Cisco SD-WAN vManage Software containers could allow an
    unauthenticated, adjacent attacker who has access to the VPN0 logical network to also access the messaging
    service ports on an affected system. This vulnerability exists because the messaging server container
    ports on an affected system lack sufficient protection mechanisms. An attacker could exploit this
    vulnerability by connecting to the messaging service ports of the affected system. To exploit this
    vulnerability, the attacker must be able to send network traffic to interfaces within the VPN0 logical
    network. This network may be restricted to protect logical or physical adjacent networks, depending on
    device deployment configuration. A successful exploit could allow the attacker to view and inject messages
    into the messaging service, which can cause configuration changes or cause the system to reload.
    (CVE-2022-20696)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-msg-serv-AqTup7vs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12d1b61a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx87376");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx87376");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_ver' : '0.0', 'fix_ver' : '20.6.4' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.9.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvx87376',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
