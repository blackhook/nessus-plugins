#TRUSTED 6578cd50e0d0df545dcb4891501eab0c103a5468269ab146c4f0e3ceeea9146c1e55aaa0ce552ae0f65cad00572674ae4327f6d353a809cf7babf0d4ccd2ee2af58aefcb19adb02116f6cf0b4c620542aba3ccb4a753d29a37119c7aaec0d0a2e035f83e8d7b7ddb5de046408a00fc51e41be3eee72da97a486581332113d1a1c98361e70d3d2afaa6d27d5ff1c52cb62837a1858f921ce465ea80dca9fd7d9ec84ca7814dd94c7761ff9b30c00aab44668268b800cfb0da2b3d0676ac1f03e7eafd670cfe904ba3ea6c8cd49be316258620da38b44424fda17967c3331b609528cd9861534a978d39a5156c75995d354402338c47ad18ef38a99332c65cf59f09f600eae7b959ff53422a5c894479cd5ea0db56d85d7ec2cc183b515e801055ae1d7d4e3490e321651f2c2b3f660f9a765edb95e2cbe961f73e74776c354939967e796db42c99d2a65d82067acbd9de7165e00aa5464bdce58ee20703212e8ddd5b3c819b44478f00283649ce0dbf9c903248089749f74c286dba0f72a1f06c6738c53e3a26949400bb78f1c75f46bbc32de69b3dfda265c1da8aecbbc9a66cc970b165c8afa3b4cd1446e20b3b28c8f6639a8427fa92a9b8fbbb92063d01dc7d72e89c2c691689515776d1e65ca207b96a2e958aa11b83d47610a392f7a3b2eeeee5b1fb01f420b8edf99e49790a991d05ba04462899873c2103e6b2447d56
#TRUST-RSA-SHA256 3811697c1b13573be1decce6763de339d222d121cab9b27740101633cd8ca5183cd653755cb4269f2b65cf1ed268ae92088e5b1c0f7b86a77a39f5032779932969f2099e1ca0c79d1a8a9a512ff494015e3c6b9f925ac8e3df1539154d53cef01aee2058132ac67aa4d9fcb5825a443291300bd3b6d028438af87d5cbbeca7a27de973b16ed3b6a339fa16ffa682d58ad8a62b6ba9d6ddd2423ec76cbe1391a085dfa27425d70df4df4859d66c532f88e9177db5562d966b499caa14d41a4e800364f4ce27f16689bb8602f6ef5249c2d836e05bd4fd97c63efe86702028da274c31cd78cb6b79e3deebc6134f35434a66e6c7503aba05102d42b97d02e0d99dc721f499542287f475c9c8cbb68c49dbd288f5db2c11ba46bb1b6763f75211899c5d7f1704cfbd281bbe6c8f32852c1c621b0e46c58cc35786228ebed003fb12dd6c87aa2f95d9480bce12dea68edb747595bad6aaa591218cdc0177a16a443ff82af1dc34a71be5d16811aff12857fb74416cb51c1fe6ba22f2baac5b022704fd48f704a53b5016cb5884770c2837bcd8d91b7cf0c2abefdf4a21d7f094c633312a8dcbcf794b54a43c33941182f2c9bd4a3c0da84c52d4e0c9f90049380feee4fcf8a31366fbf39ffdecde842ba84e1e3bf2808545e1a14dc073134f2839d7cbe37a0784616e2a84dd0bd5889ae7f2cc6f8338a6eedcaad651683b0e426d7d
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165533);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-20850");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm25943");
  script_xref(name:"CISCO-SA", value:"cisco-sa-arb-file-delete-VB2rVcQv");
  script_xref(name:"IAVA", value:"2022-A-0391");
  script_xref(name:"IAVA", value:"2022-A-0390");

  script_name(english:"Cisco IOS XE Software SD WAN Arbitrary File Deletion (cisco-sa-arb-file-delete-VB2rVcQv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the CLI of stand-alone Cisco IOS XE SD-WAN Software and Cisco SD-WAN Software could
    allow an authenticated, local attacker to delete arbitrary files from the file system of an affected
    device. This vulnerability is due to insufficient input validation. An attacker could exploit this
    vulnerability by injecting arbitrary file path information when using commands in the CLI of an affected
    device. A successful exploit could allow the attacker to delete arbitrary files from the file system of
    the affected device. (CVE-2022-20850)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-arb-file-delete-VB2rVcQv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4c2f71d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm25943");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm25943");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '16.9.1',
  '16.9.2',
  '16.9.3',
  '16.9.4'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvm25943',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
