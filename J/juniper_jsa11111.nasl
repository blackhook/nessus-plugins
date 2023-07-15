#TRUSTED 4b07100b2a5b7a323e0155976bc5e7de0d80adad896e70a36dc1b805fe6109ce74bb0ec365a9b8ef789b3f9e95ad06d77afb39334f7b458a41b7373ee761dcda984b806432f3eb06bfd3fd174dded3735745cc8741a24d94de2fbc676f04edc84a1b6fc030302247b175ffa0d1270b8b15b909d3763b1147384a8ed4642e8c0fad83f5c5a3f64478c924c5111eb9a45ca057747776da19b4ea9789c16ce390ddd704d164bf6fb5573d18eed3798d37ff7ed00c5c259c7cf54d3c17461bf08f4d7ac1a06ce804f3ce5cdcae903d5c1f4b1790d5d68feb8f85b7af9e6e58aa7e5bc0048f46f1e02d4025f9bf970b99f6fdbaa9a6e88284c2dc77a5e80f3699706e9568e93e01f09b9925f39d5a46b9ab4d6c8e9d07270d3372e68c5449d3307d073c5cb170170e6138ec266c3a0e7cac3cf80a2ed277bdb7f8553b84f5cb1b02bd1fdd99273b2fda756fb8d925bc65d886d1c4b4bc8808f1bbcf74f2e8e1d455dbb348f503fa515b9e45bb3ecf57fbe7a32e776423db40f124aa1f3029aecb87ce91419d8be580b3d5b171254cc9011a6777649211f5e20d711b7a3759b94ee3976980bd8deef22526f9d4154715fb52ac93cb99ef17cf24f667e7c023abba1fa6b6fdfd76332e1f814cba8b1556d78c45b1965c1226ef9ec908aacd51b4b996f1f7b2f7537681e0dc08eab455286fe6f2a5f05d740cf11e49e88011a709d9e8c6
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144983);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");

  script_cve_id("CVE-2021-0221");
  script_xref(name:"JSA", value:"JSA11111");

  script_name(english:"Juniper Junos OS DoS (JSA11111)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced in 
the JSA11111 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11111");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11111");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0221");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

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
if (model !~ "^QFX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'1.0', 'fixed_ver':'17.3R3-S10'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S12'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S11'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S6'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S5'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S5'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S6'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R2-S2'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S3'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S5'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R3-S1'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S5', 'fixed_display':'19.3R2-S5, 19.3R3'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S2', 'fixed_display':'19.4R2-S2, 19.4R3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R1-S2', 'fixed_display':'20.2R1-S2, 20.2R2'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
#set interfaces irb unit 100 virtual-gateway-v4-mac 00:00:5e:04:00:00
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:".*interfaces.*virtual-gateway-v4-mac.*"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);

