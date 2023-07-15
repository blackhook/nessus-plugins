#TRUSTED 8e3a9a2531dbb844568b162a3948938923e8361ab6898d1ddcc3afa7f1b345bccae2656567d5c66a52a99d7c39dc7a77646f36849e8fa24e6a86494d7126718497aa3090f32ef7a707bff1a5d371b470215e1e3067ae898c5e83049d422f31beac19a29a78a7f2a4ee27a1f29e826f4dad0f81b5c9abae1689b057e1e5c22b5ed2ca69b0a510cc9035a793e645ca6d5fcfa25916aaf7aa38ce435a9086c276cbe56144228c048b619c4eed00de13b34330f1d185de8140cab3573cae3c2d5ac83f2afae1dd0bda2d7461a1a538a31eab2bc33972c9ad592db067efb1c6a850e0bea9fdf93180b48ad47cbee50093a8ec738df9092f220077ebf1bc8901b52d69a3dc2ff0eaa755bc0da3ae3c9abed66cc058846182f11f7267bbf3f4f584a7cb7b031818c650be4fe256c3ec0763042d1a2a0f0cb76825fe2d160f405d6306e783aa0a08c93683cd16ba6adaee49159f4c46d751e59fecbaa88abee6be3c816208cec50eb3ce54e3f6934e945fe20bfb3dfd91bd6b970562fac7afb8e77d58acc1340eec5184ff4e2fd4803478dfdffb33c3c76f6632d9cef61d70beb39f07adba813cab995cc69e828a46a3dcb14ecca1a9be5fc5d7f6add91bfb150ed694ae9e0fc72b784b1b0a9a4198a6af5f6d295327d702581a0025028585ec32a97b33da4044ca55bd09200f742a675bcde817733c9dceabfa763c7af1b2b6e76b029b
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149970);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/27");

  script_cve_id("CVE-2021-0237");
  script_xref(name:"JSA", value:"JSA11132");

  script_name(english:"Juniper Junos OS DoS (JSA11132)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service (DoS) vulnerability. Packet
Forwarding Engine manager (FXPC) process may crash and restart upon receipt of specific layer 2 frames. Continued
receipt and processing of this packet will create a sustained Denial of Service (DoS) condition as referenced in the
JSA11132 advisory.
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11132");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11132");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0237");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX43\d{2}-MP|EX46|QFX5K)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S9'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S11'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S13'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S4', 'fixed_display':'17.4R3-S4, 17.4R3-S5'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S8'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S7'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S6'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S4'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S6'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S1'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S1'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S4'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S1'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2', 'fixed_display':'20.2R2, 20.2R3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1-S2', 'fixed_display':'20.3R1-S2, 20.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!(preg(string:buf, pattern:"^set protocols l2circuit neighbor .* interface", multiline:TRUE) && 
      (preg(string:buf, pattern:"^set protocols mpls interface", multiline:TRUE) ||
      preg(string:buf, pattern:"^set protocols ospf area .* interface ", multiline:TRUE))
    ))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
