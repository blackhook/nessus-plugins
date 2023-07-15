#TRUSTED b20f8baf0af284f8cedf12e94b5d0ae564dbdcc03c5af29f30f16caab12a8aa9e26596ee9a9c5ebb1257f830ac65619cffcf36c9a5e5e76911369a5df6c145d5252424e27c9a06f8cfca3179bebe6081e8e550031652e986622e207277c69f74cb2c35894ad2c2c336cbac4d3dc6002ddb7c1a4eb7bc402652cd094d892391f730c41187bda55b44d35112bfcd783071ae94f37b05c13aa09e215364d8f3df7a2554f6fe9f4142ef56ab6b9e40f6c05f038a10353c50195a34fe1051113bfc70b4fbabe258823dd0307e07906068c31b14638f44855aa77013323804779cd1ba2a9013d9fc3b82433f5b52175086e036d18c681999ae8cd9edfe35c17facdcadeb5130e0506fb561399d881012ec20d9d7f4ee2588d07877eb72bcff39a15d32dafe386f55db7a1cb3d28c8d100b0c69c02daf0dea196cba47564454803cf7d4e878e0602a33c291ef0cbe848c17d17ad1cb7e16814f5f5aa161eeb1b0f180b2a308246e9e7d6729c3652197b6fdc93d938cb18d26681a5ee36bf4aab02ec1e409bcdfb1f53a25636464c89da498ef03ad994725414a8e5336e6d63cf8da144f32269d675c40147fc859d73422a04b3b2c3d9dfe0cdb338e5c8f0d827ac10eb1f8eb4dd570b39c43fb53f3c9b78d7edb1fe50966cc730cceceea6af001fd191faa9b14af97c917a89d18c239658ee233a589124113f6a143f2b0442ec21c5202
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146106);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-0210");
  script_xref(name:"JSA", value:"JSA11100");
  script_xref(name:"IAVA", value:"2021-A-0061-S");

  script_name(english:"Juniper Junos OS Privilege Escalation in J-Web (JSA11100)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11100
advisory: an information exposure vulnerability in J-Web of Juniper Networks Junos OS allows an unauthenticated attacker
to elevate their privileges over the target system through opportunistic use of an authenticated users session.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11100");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11100");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0210");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S17'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S10'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S12', 'fixed_display':'17.4R2-S12 / 17.4R3-S3'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S11'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S6'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R2-S4', 'fixed_display':'18.3R2-S4 / 18.3R3-S4'},
  {'min_ver':'18.3R3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S5', 'fixed_display':'18.4R2-S5 / 18.4R3-S5'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S5'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S6', 'fixed_display':'19.1R1-S6 / 19.1R2-S2 / 19.1R3-S3'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R2-S2', 'fixed_display':'19.1R2-S2 / 19.1R3-S3'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S3'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S5', 'fixed_display':'19.2R1-S5 / 19.2R3 / 19.2R3-S1'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S4', 'fixed_display':'19.3R2-S4 /19.3R3'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S3', 'fixed_display':'19.4R1-S3 / 19.4R2-S2 / 19.4R3'},
  {'min_ver':'19.4R2', 'fixed_ver':'19.4R2-S2', 'fixed_display':'19.4R2-S2 / 19.4R3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R1-S4', 'fixed_display':'20.1R1-S4 / 20.1R2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R1-S1', 'fixed_display':'20.2R1-S1 / 20.2R2'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix))
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
    pattern = "^set system services web-management";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as J-Web is not enabled');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
