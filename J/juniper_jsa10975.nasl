#TRUSTED a69ccf2ba18a25b9cb3acca2d0f4f19768d1729a27cbde993b9dfc52fa9f46cc0b0cb51d1af47bbb5daf77bdcc4ef40e7f88dcb422e17fa6530358cc0552d20f976837e59af4e25a01dd3bd587b06642bb8554d4ea1f5c286aa21b6dc33ff4e7b59201600da76a723795281358c046f51e61b4f2a85d84d9a0fad1442d1f8b27a67b9a63ba4f1a8dac51fa6e775f346a2410cbd1f099f4c6fd824e1e80b5849fc0d605c8b58bf6d1c74e8fb6d4d9ee5194e3f1ac86fb5a214c729b03579628e4592f815d1911f40993df805be919f89c1559a892be1d6204cf30c038d1317152832243b27663102d0c16e1dd09779280865289d88ca85729c2c308dc12b18700027d726a76d06445e16576fc5876bb6c427c7af586de5ce146a73349b320ed556e0a7ceae13571ae3e416e7643e3e0e472992899a3e57f21672369c73ef1d41f12d70088d456271ec27529c1c10a177755a7a890f7a839fd0240738c4fb2a018a80278d43aca660a2db90cc5e7a86d82369956a2ffd1cbf18d32d4594c425e64cedcb6b4a95d279be59470eb1a68c248bb396b24b6208f58b8d0e56057cf53f38ce1734af6f7e8621f6cdc1564db380c66277c98dabb157627b0ef0bce4d126d6e22f6682eae95525f5c0309f9a8c9c31af09bd573cde5931058de6ea765f5e43118827a127d5b905ea418ffc3f49edc54e9c99a385959c9b9514215fcb6e394
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130279);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0074");
  script_xref(name:"JSA", value:"JSA10975");
  script_xref(name:"IAVA", value:"2019-A-0391");

  script_name(english:"Juniper JSA10975");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to the self reported version of Junos OS on the remote device it is affected by a path traversal
vulnerability with the Next-Generation Routing Engine. A local authenticated attacker can exploit this, to read
sensitive file systems.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10975");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10975");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0074");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if (
  model !~ "^NFX15[0-9]$" &&
  model !~ "^QFX10[0-9]{3}$" &&
  model !~ "^EX92[0-9]{2}$" &&
  model !~ "^MX" &&
  model !~ "^PTX"
) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes['15.1F']   = '15.1F6-S12';
fixes['16.1']    = '16.1R6-S6';
fixes['17.1']    = '17.1R3';
fixes['17.2']    = '17.2R3-S1';
fixes['17.3']    = '17.3R3-S3';
fixes['17.4']    = '17.4R1-S6';
fixes['18.1']    = '18.1R2-S4';
fixes['18.2']    = '18.2R2';
fixes['18.2X75'] = '18.2X75-D40';
fixes['18.3']    = '18.3R1-S2';
fixes['18.4']    = '18.4R1-S1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for NG-RE, if not output not vuln
buf = junos_command_kb_item(cmd:'show vmhost status');
if (junos_check_result(buf))
{
  report = get_report(ver:ver, fix:fix);
  security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
