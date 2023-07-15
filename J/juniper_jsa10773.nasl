#TRUSTED aa11153edd27726138b4ec44c5c04646919ca9d707475505082aa3373b2b6a4afa3c09b9b6d270f0a28528669b06fa5863498839839bfcaed6219aff82eb98f41fde4e80a02c74bff663f949615a870ef655bbffeab113cca235b34eefec07bab058bc3a78842b2e90abe1cdf1f63a003b022c3b7cdd800829d3a5b3d15bc90f780f99ce51884779a17768148a5f860005f096b7dfadd31f40de1cf3d9ceb9d3c2da81134d8f54fd488bf1c05e8f0e6153cbc03e0f97074b1dc6216eaa3c211c71a4de47ccee4d12db73ecc53a14c20b23b172d5b2b94d6949b225bfab987d2cf06b5b03791008191525e9e522bb46a821a2e70dce90c7be0e58f967dbd3b6ff163c998d7241d076b4df08baedba0477cd63dc364dbb38ad63b78f54fc8d241fa156451067cbb863a5912294cc5ad5720ce4e64195f0c677b07c0c6a26594b783a9b3dcc3e9653c0fe5710ae8f3d6aca20ea5414b8456cf83ab09dd93a1089c584f014b91a7743330477807423fd437cca34747a5b5ae053a2c919b0e90e054bed68f74828af926874611580c2f51dba898815e61708d443735c0d06b3b79190a1259a6472dd5ddc600184cc6cd0dbf839313b0c8811cb39ba2ae50421bacc7314cd6d3e0fa40c83a6e4f84154418ce0278bb1771f5e58d686eeaf08656e1f43c801aeb3853336b010df4742317208c29cf9f55eaa26e13fc8ab9fb4a41d661c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96662);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2304");
  script_bugtraq_id(95403);
  script_xref(name:"JSA", value:"JSA10773");

  script_name(english:"Juniper Junos QFX / EX Series 'Etherleak' Improper Padding Memory Disclosure (JSA10773)");
  script_summary(english:"Checks the Junos version and model.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a memory disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos QFX or EX series device is affected by a memory disclosure
vulnerability, known as Etherleak, due to padding Ethernet packets
with data from previous packets instead of padding them with null
bytes. An unauthenticated, adjacent attacker can exploit this issue to
disclose portions of system memory or data from previous packets. This
issue is also often detected as CVE-2003-0001.

Note that Nessus has not tested for this issue but has instead relied
only on the device's self-reported version and model"); 
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10773");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10773.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^QFX(35|36|51|52)00($|[^0-9])" && model !~ "^EX4[36]00($|[^0-9])")
  audit(AUDIT_HOST_NOT, 'an affected QFX or EX device');

fixes = make_array();
fixes['14.1X53'] = '14.1X53-D40';
fixes['15.1X53'] = '15.1X53-D40';
fixes['15.1R']   = '15.1R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_NOTE);
