#TRUSTED a822c93cedcef920aeaf460d3d8c2064acf38ea98747b0c894a0fcf3805daf55068762f849c281e59998e1c0378b09b81308903ed9ed3298a27fdd4ecfb72c2e9d80ee492cb81f89fcccac958cc7017cd75fc4296ba72e842b702970ff2334aec2eaab31ddd8c2f1c50f8531dbde5d991e30926c578b9bfb3991c4561ded4057166493ebd0e59434d3b99f192e24b6fa4e97e7038401add9c00c237f9bb1cb4b155e40726d761e5f966b552be374d414998431e4c58c92e9f4bc7e8ac88e594f6b47ef299b5b998d1bfb087cf80977ce3d96ae20fa5a3bc83a18fb6168e88f1dd4ff8ef5f46a7bf276de738d98fed271cfd7cfa877586219c38924e9e3ad9a66dd3eb01aa805aa9ee2ce437cd152162180f7bd73653f71019a6b6d3603f8190af970b0ade92b64e17f771b1aeaa3ba6d982f85bf1fd30dc4c134d9c41fd40d24ddbdab3d6b785314632d54d526441aca65e3ca04ae014da0c4160321da5fa9aceadb928d49babb7ca3c51b158efc8aca2159bc640390887a9ed671ecda6bed206582c3dd7af62483d9f8a1c7fbedca7da83b8d36597f9aa33a147e546f4ff185f3cc1ed05bc24cbe33166714bece1f6ee4c5501cbf36173c509290f36d330d8834f72bcbd0b55d7a6ac01ca397dc6bf501f4518509f56bbb78e8be27fca38de0cbc78dd1b47ff6a65a91b5fc48064815941571fd51d5ad6e6a7bb450bb71aca2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92520);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2016-1277");
  script_bugtraq_id(91755);
  script_xref(name:"JSA", value:"JSA10752");

  script_name(english:"Juniper Junos Crafted ICMP Packet DoS (JSA10752)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability when a GRE or IPIP tunnel is configured. An
unauthenticated, remote attacker can exploit this, via a specially
crafted ICMP packet, to cause a kernel panic, resulting in a denial of
service condition.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10752");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10752.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X46'] = '12.1X46-D50';
fixes['12.1X47'] = '12.1X47-D40';
fixes['12.3X48'] = '12.3X48-D30';
fixes['13.3'] = '13.3R9';
fixes['14.1'] = '14.1R8';
fixes['14.1X53'] = '14.1X53-D40';
fixes['14.2'] = '14.2R6';
fixes['15.1F'] = '15.1F6';
fixes['15.1R'] = '15.1R3';
fixes['15.1X49'] = '15.1X49-D40';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show interfaces");
if (buf)
{
  pattern = "^(gr|ip)-";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because there are no GRE or IPIP tunnels configured');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
