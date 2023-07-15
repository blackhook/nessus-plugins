#TRUSTED 56d9559bb5e3775b1f5f6be60354e6950d7ea5856c6819d04f2c678cd40bb37d2a76b19122718c0687c052e657392a7a4f6451a04fc545c10cb47ca67eb5b018224b85bec275951f8780da1932cef036a92b8fd5ad71c7a50d7a40c9a39bc4a998971c1cc992b38add7522c160c3d62657d32d2f0b9b71636f4e4cac915d6e3d12dfb2116d55ee47b7513020c34142e352088491e87a2e0ec20ee0a6f6388db8eda1afb393a3ba78cc140d05c8a1b307c3b6ec3b6ca00296ae4005f05bf90e391906b650db76a57a6835a55e8daffacd5870e8c7e58b1ac091463e750f1ab4487f3979057b0fcf2c5d86dfd1af00eafce6a306beb1773e8cb37d6af347a1b84b57d4775e94b44dfbd5a3cb3a7051bdb369f4258c00f6ed1a0762ae585dc2e52f1541a57978537af32dc4211e2698f09eb260fb18f69d87a5c92cf25be5c29107da55b3c6e3dbee6f6ae5213e68fd035a5406c9dcb585dba2c917b3f9e4de287a105f8d095fc55e37e20996374640be3730dead519081b76f0332df573b9dbce9bcd2424632852b10cda3925db2c64fed5bf5166c6f2b467903234c64af8d66d82fc497f4d49f2be12d60b9a7f1b823136a6fa7b777cf82645980cff093e481c328ccbb8260cfd66829eab58c8e4097fe3a3a8290c597c3346650ca9db11d74a01121ade23e5d470375d46c5489cb46b859fbc9fd44a024ac5cfc86b9170b3ba3
#TRUST-RSA-SHA256 3840e4e1df645ae9c7f79bf7ab9c20fc6faccfd4debb1016966377d3a9f74ded072d50115a9a005555b810ab458e91c8f7c09cd6ff543e578ca7a29fd95c6ee84121518354200ef0a41f19a494a5af1c66ec167ea8be84796faa8a6c1fe0319dde4823b5952ac8ed4f59e624ff288ca73d1eb59b40da0d7cbff4fd94fa2fba4bb6589d83893c4424652195869c175ea18556420adcd7cb1d2c3bd19900d9735422ebbc4c3a64620b52af1dc7570fcf395dcbcb7b268b31a8d08f8f2507abaf152ceef0738cc873324ef595658d964a09a50da8f86c02d30579a071508519c387e658fcb12297c9f7c2f66e1da49f1b7b2ef803be6d96cafe60e2befc22539919246acc581305cdc041271f49d57ecc353a7fd92a0b00a8390fb73c87fe4ef316225a0a6f4a77d82d2630baa3636fadd5aef403be653d1511b51aaa4590d564ec6998fd709c590e4e9f272c24238a60e40d428475d4e37590873886d93a753b4c50b1643b22be2f0cf862b5cadc42631ff82139dcb39268c235b2f5da67adcdb18acdd85d137d8a153ce0782674874de9c1c1209cb90d4cd26dd7527cdb1ad92ff7b7600952c1ab3fd8d25b8872481f57bcf09b1f381a1ac98a746e8739e0abcf294f000e567852ebd72309dad136986e0d17a84a7d1f2deef339243e6f475c820ee9fed864f795d760b5dce7513b71cafe429afb8de24f3e95c536b0c36fefe6
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154853);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-34761");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy41757");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-file-write-SHVcmQVc");
  script_xref(name:"IAVA", value:"2021-A-0526-S");

  script_name(english:"Cisco Firepower Threat Defense Software CLI Arbitrary File Write (cisco-sa-ftd-file-write-SHVcmQVc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability due to incomplete validation
of user input for a specific CLI command. An authenticated, local attacker can exploit this, by authenticating to the
device with administrative privileges, in order to overwrite or append arbitrary data to system files with root
privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-file-write-SHVcmQVc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad9928ad");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy41757");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy41757");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34761");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(73);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.3'},
  {'min_ver': '7.0.0', 'fix_ver': '7.0.1'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy41757',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
