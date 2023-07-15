#TRUSTED 563b82933a72ef741148c9ca344cd3fde84430fd9b5e79813e40eaddff59ae7db9a93d5708926cf51965317045c6dbea3bec1547f3d551705d067921171d310543164c54b8c28599a5bc9a7d030f4442d8320b50575bb5bb80d14247a537cef99af8d68926a317685449753302412c8e0d1c68cf7580b397c0a5478ae9a641495327af53c5bae3c16f403cec81c0cf69ba06e30f8ab679638bce85afac85053c680520ce54f3dd7500561259724c412e27443ef488061bdd10d16e2533671922f3faf2a20cdb0a0cf93f509263da2b8091828fcf2d81f000a7fd11dc471c6de021544b13358e42994e1326e48fa540e3b4960f603265cdbc2c6f38205c0dc701421ff85953935a7d6e70bdf11d9f5839851b95dda82eab235d745d9cd11a71adb84523871bff29dd7dd79ed8e9a43bb1d4c2bee199a9033e340d6a54cda6b824603f3d68b56abb7d0fd680990cd3a22d92778168ceec727f42e140de903e89325d075f59818f0e44c0333ba2eed7e29d9ccefa5309df01b691126d7f817affb2be731140f00a35db6bab63d159e70bf11e0f04a124685fb93b59591dac889afc83a42807488cbb36d1d7a5272b2d842c6ce56a5f37850f71426f8f0c7a2119f5489751ae2d7047bd52c82f871440e1b93f67372da1c1e42eb98703a21b4acf17ba6c098c76df65552fd73e5f1021bc27401f6b51abd37ead67022c22560e4c7b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144933);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");

  script_cve_id("CVE-2021-0217");
  script_xref(name:"JSA", value:"JSA11107");

  script_name(english:"Juniper Junos OS DoS (JSA11107)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced in 
the JSA11107 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11107");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11107");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/13");

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

model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX|QFX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'17.4R3',	'fixed_ver':'17.4R3-S3'},
  {'min_ver':'18.1R3-S6',	'fixed_ver':'18.1R3-S11'},
  {'min_ver':'18.2R3',	'fixed_ver':'18.2R3-S6'},
  {'min_ver':'18.3R3',	'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4R2',	'fixed_ver':'18.4R2-S5'},
  {'min_ver':'18.4R3',	'fixed_ver':'18.4R3-S6'},
  {'min_ver':'19.1R2',	'fixed_ver':'19.1R3-S3'},
  {'min_ver':'19.2',	'fixed_ver':'19.2R3-S1'},
  {'min_ver':'19.3',	'fixed_ver':'19.3R2-S5', 'fixed_display':'19.3R2-S5, 19.3R3'},
  {'min_ver':'19.4',	'fixed_ver':'19.4R2-S2', 'fixed_display':'19.4R2-S2, 19.4R3'},
  {'min_ver':'20.1',	'fixed_ver':'20.1R2'},
  {'min_ver':'20.2',	'fixed_ver':'20.2R1-S2', 'fixed_display':'20.2R1-S2, 20.2R2'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set system services dhcp.*") ||
      !junos_check_config(buf:buf, pattern:"^set forwarding-options dhcp-relay.*"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
