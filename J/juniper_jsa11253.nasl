#TRUSTED ab038f799dc6b2603301fbefe4b3d751f0044951a69ee05b61ff5f8564113582716ef28b0400861fa86a0c6434939783545bb215812176c95d5102871156d9df3176600c64704418ea73c7ebc14dcadbd31e2b015ecc92db11486818d481f32eb2034b777b97c55e7044755755d444891c2eae5306eae5a2e3dc4099e338d2c1d54c321fa230196467168a6db78923efe5c86b17f5b9e0db3dcd15eaeb4eabcf001af3a1cb921d144a88ffe6ff98231a13a7d4b73c2a6c2260ad281842f642d63a7d75255d9a09ee0977a32dbb8674aabc0210aaa7a33a2d70db4189f9d364eb8a2f06facd1ba65f3518f2228736c1d41b1090589a4afb45fc7f71e9e406061f4c77e4c0356bdeec63f6c8609313c0c89c11e3fbbece7d2ac4bde989a8d8d64f1cc92334caa46fc58eba556427b2c7d7fcf6971126f56a32822fd404e593fc4f4c4e401815ebdcaec35f9fa334436afbf33ff4773647c22ef756a0d1df294a5ecf6988f6575aa564ec71cf1cb65c3e979ae8c6ccac1dab59e0476a88bb89da14e82ec6b2d982e2cbdfb4ef08ee56fcb21f8434354eb8ff66e071d979f0660d106a769df8588b5933cbda878645a9703826f361a273e3ed664fb7c4187d3385238662cb87c950bae91a982e140b72c8033e5877f3afc67ac97bccb7eb446836ee8193ebb0eb33b9b3442056098cc11d6038757261687e9da8e3ef72f11e685e21
#TRUST-RSA-SHA256 0db7e0609bfa27727927d762aadf05da9ef04f01cd65b08d9f3a78ca44de304c56a7f5fdd30bfd49cbb22ec1f63195b1487f4767ea07ed804e769814f8a1b444dddf4b590cfe799169bab1d4f075c6a7b790284b608e6286946e39345cd5fa8b692e95ec94e1358a0adde3993215a4fec22bca8b78018d37957d199c9e4fd680be82444058851aef57b039828c055d46a25e835533682a8752f23a392f592b0a4e6fe52fc8faffe087217a649890a1ebaeb9472572dfcd5ab31e6419c4d30e86f64287139f2bec40d8935117757b2690b844cbb6bc814532742fa520835a5d6818498ecdfa98c766eea7bd37acadff60d396834930c4b55f04290439c42240c24947d8c8bea9b739808b5af53a8c4ca5ddb7c712dd58fa914920ef522f9acb0c1d550dbe2cece051b1e3ae7af957a4d1ced81fe7267fbd8cf2101f4c3e4ecbeb041b036c693a744767233b3630d8c5eff9a3a1f127b90a6477d4755264b07b37bed84b45074e8aba91db66e0007e2c547b72522a51030d4dfcec7d1f08ae15e0e04f5ea2502d6d525288a6c3f74726a42b5de151acb14ff8cc8631755850c30871578b0a1a0a042b09691b7783712139a11040e2a474cda7f357a6e5d1a8293409728bc6c2098f56b37fe50fb235a0a98f83a70eb2c7cfd05d15b00030c6d696c4fdbfb5abe4df616326821b45b15b98d3763fe83d62c2807d4ae2ba2c006bca

##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161953);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/30");

  script_cve_id("CVE-2021-31385");
  script_xref(name:"JSA", value:"JSA11253");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11253)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in J-Web of Juniper 
Networks Junos OS allows any low-privileged authenticated attacker to elevate their privileges to root. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11253");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11253");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S19'},
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S10'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S9'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S6'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S7'},
  {'min_ver':'19.2R3', 'fixed_ver':'19.2R3-S3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S3'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S5'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2'},
  {'min_ver':'20.1R3', 'fixed_ver':'20.1R3-S1'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.4R2-S1', 'fixed_display':'20.4R2-S1, 20.4R3'},
  {'min_ver':'20.3', 'fixed_ver':'21.1R1-S1', 'fixed_display':'21.1R1-S1, 21.1R2'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set system services web-management"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) 
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
