#TRUSTED 5182e69d761938fe98ea73d95b3985ee7176c258810a7329d19fa4c68f541601480a47bbf2cf8b4d215696d960829d42a6efecd750faad2432704674d7d39132236035a8b913dae1cd1ee41ee90abf940dfbe3ec974fe987c3742d54522730038ed13ce68a4ee9a624d375cfd5dbf9395149e00734b6340eb9255ac2b6a3f5cee7f859347671d01064aa6fe526cbcfbfa4dacf700b434f492b3de7e7ea8e7a3723dd12b73be584a55343d20644a8dfb89a6ec8297d0d24676c8ca20149e5c8779419c65fac8c884c4b0ed9fac6abe6b104d8924349d03e044359beda8665274a3978848ffdaefe25ea5e9d320526aff4d4e972aa27e3f26683ba1e016f1eee872221242fd9f6596703594dc369269bde4f87bdb29696bb700435045c056c245fb90e4b1bad8c1414739bd26eb7adecb465c319752ee11c1b6d511cf3bb848e9681cab812eb4c8492bbf9ea35421175398fd5383792760ea0c0c6bb1009ee100f984d3fe81ac5235d66604cee942ef7055ab35a4b2dd33a3a1a9176f2a16da152ca2e567f0f1ef54484486dce6387d6ecab956143bd5246d0448b6dcdd005d094222400523661ac7d66212a5b4f29ab89d887bcdbe9ca14c4b2cb9635d0ec359d8805f3de43460026f2e7c04a5d3e106574462b21f55a6cc19485f1a12a435441894eb952d1fc7068b16490ea6de232369d40b08806db0b7c2a7785cd8b918168
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94333);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2016-4923");
  script_bugtraq_id(93529);
  script_xref(name:"JSA", value:"JSA10764");

  script_name(english:"Juniper Junos J-Web Reflected XSS (JSA10764)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a cross-site scripting
vulnerability in the J-web component due to improper validation of
user-supplied input. An unauthenticated, remote attacker can exploit
this, via a specially crafted request, to execute arbitrary script
code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10764");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10764.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");

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

fixes['12.1X44'] = '12.1X44-D60';
fixes['12.1X46'] = '12.1X46-D40';
fixes['12.1X47'] = '12.1X47-D30';
fixes['12.3'] = '12.3R11';
fixes['12.3X48'] = '12.3X48-D20';
fixes['13.2X51'] = '13.2X51-D39'; # or 13.2X51-D40
fixes['13.3'] = '13.3R9';
fixes['14.1'] = '14.1R6';
fixes['14.2'] = '14.2R6';
fixes['15.1R'] = '15.1R3';
fixes['15.1X49'] = '15.1X49-D20';
fixes['16.1R'] = '16.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "13.2X51-D39")
  fix += " or 13.2X51-D40";

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the web-management service is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING, xss:TRUE);
