#TRUSTED 45180d9adbf574888e43642463eebfd6b6a285eedb9014521e35ce27566feab70d02b73bc2af5ae3fa9cfe19ce41291e08cf806809cbf5422e0e82fbb102de28fa08db2fd11df1904dc244c4dc40dffb2aa4fc867db29e3b3673c197403526404172930b686e514d74d4041e3375a3c58a4a3a2964026bd25667a0c464d9e7d92839545ee448d74e0f52898662b80ca5cd4c8591c517aabfd578577c27cba860c21e897fc7177facfdeb154b69446e8f3a7dd550c2b3fa918e3308ca1aee1def57fb08b576016b687f74e5c49f34d28d59314bb9a254bb53e790daa3861f08b46aa09692370b663ba00de984dbca915c81373e02aadd493eb9302088df8de831db367c620c694976f92c16eea41264311bec8fc9760d6b2bc3a3d00479048d49ced901c15c1a214f1d66d40deb2dc7ba144bdc56b6f63ca7d130663c6d8ee05f720db85d38bc8798d3070bde39165d37691c30a058e804d02f350260c636b74431ff7cf1ebc40f3801d6d521d770c88977cb7bf2e9a1ee0e071e2a01f6e3d00aa57728dad568eb292a6494d5fc55e73034f2f203ed0575f053c41d5c247b835b55aee53ef3d9a0a00554c0aa5a1e2be9260eb16d22f7bf5ccb197f38bafea00b924b4ba06542910d9f9dc803c879798ecdf6b043bf3f2921ef985006652b21972a51b121d6d786920cb8dfcee323bf30f5435a619dfa224d6680d84d26410415
#TRUST-RSA-SHA256 526fca9a29ec3db037cddb43580fd8127623a55cfabf139689c9ccf0173d58950460da55298bf9cb399746bc8109b8c55bf10f5a7ee3a146f392de9c2194600d6335e9186e7a43ca7fd7e9d20a6b2d560301fd5dd229a132d227b3c8ceee31bba50b7484762d8c62f01094b145d3f10771aca1f8c5e543bc15ab2477da5f3678f4b344f8c13c25c1294eb9b4eed242d53066e611dd07da9289f7c0e08060e950d16aae8b90c48e3facf89b4649f755af67b62106fddce657438c7c2cc69d4f2f9371d557d7ee36af606571bfff260a809c9013d25e94767476bbda913d00458388489d330a0884e7dd852522fe5f060da6496164405e86ed0119a541376c39f6be8abd00061addd7ae84632ce86f8411966f36dfcc042dd07f43bd26bb67a742b5ff7394c44f65e74930de70f75a08c489e2d6bf75a2c114605648455123bb631ae53a2fa76df5365dea4181b536a1b371c5976cb516010cf4a4e2ebd2adce5d9daefc7564d3dc0a262c656b5d047b55349c1e636aa627d95e3670b9f88f1a70ed75e8051e048dd097265e49d2cdc25ca8c945b0073a886138d0f69585c99cbdf0da6084c698cad831c17af7630eec4e277ba942d4feb8e8ff9695cb485f7d63c8465629a6ee4d3c3f0cac6a5637b1e5116068afa4a3158bb46bd455f8c722d5a8669a771cb9bc83ba50c8d22728106e55db80e1fbb407d8d4af8565af465e1f
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154829);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-34787");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx47895");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-rule-bypass-ejjOgQEY");
  script_xref(name:"IAVA", value:"2021-A-0526-S");

  script_name(english:"Cisco Firepower Threat Defense Software Identity-Based Rule Bypass (cisco-sa-asaftd-rule-bypass-ejjOgQEY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability. Please see the included Cisco
BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-rule-bypass-ejjOgQEY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7905c3c5");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx47895");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx47895");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34787");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(183);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("Host/Cisco/Firepower", "installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5', 'fix_ver': '6.6.5'},
  {'min_ver': '6.7', 'fix_ver': '6.7.0.3'},
  {'min_ver': '7.0', 'fix_ver': '7.0.1'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvx47895',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
