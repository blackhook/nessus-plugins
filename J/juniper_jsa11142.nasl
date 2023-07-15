#TRUSTED 049ecef13c63089ff723ba0686b7ab0dd5fb20b59911fb69e5e422d48185a6403e8dc5d4d7966cf1c5ccf6dc0d3082257dda4cdde70beb84ea92bda5e46a13edce6f2e4fdfb8116a764b0e5e8571363cb1780d86de2042168037dcf93f4e93c89b0a76fb1d50c3167681cee41439ca367955167c33a4b82e1690c1d9a93eeef58d9d112ba02b906deea5cf1644323345c7ace8e4927cee3241107996452ccbf0a4ae848004173e04e31e38f9f72ac4164f80a1e313f534823423f45997c337778852e5e4a87b0b6523f50e60f87785b4b1addc70b09c1baed9cdbc71ec0eca8fb79939b3e931c6229bd6339a4e4d7825a7b5d02e7a50c11f2e2032d91c1e86ea5b75612b9dee27cb61f841bca9f7f38ab0eb37eb675afc467bbd38a0feac1808c150b2d210b753f4de44dacac5224d1b4320621d19f103997aa89d97b25b172b6b603829913b0a4d300ff7eeb58309d65eb29b0fe47ee9491adfd326790e43f81237b9d4f092c37cde261dae6345256c554acced27b164738e1721e231d2981e6e847b2da2503cc267e1262090a4a547fd1e0553ec0e677acbc1ba43bdcac5fd4a10f79bebc1ab8218d1172fabe51c93222a98a8de8e45949ab69b0758150c8424c945a76bc190494e421d20593ea1fc02c1c272b4001b2a1c69ac63a9fb8b0a57c049535d651adb686a954e22bf12921b2bacc1ec66690d7f8549cdd9516a0c
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149859);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/25");

  script_cve_id("CVE-2021-0249");
  script_xref(name:"JSA", value:"JSA11142");

  script_name(english:"Juniper Junos OS Buffer Overflow (JSA11142)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11142
advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11142");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11142");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0249");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/24");

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
check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D190'},
  {'min_ver':'17.4',    'fixed_ver':'17.4R2-S9'},
  {'min_ver':'17.4R3',  'fixed_ver':'18.1R3-S9'},
  {'min_ver':'18.2',    'fixed_ver':'18.2R3-S1'},
  {'min_ver':'18.3',    'fixed_ver':'18.3R2-S3', 'fixed_display':'18.3R2-S3, 18.3R3'},
  {'min_ver':'18.4',    'fixed_ver':'18.4R2-S3', 'fixed_display':'18.4R2-S3, 18.4R3'},
  {'min_ver':'19.1',    'fixed_ver':'19.1R1-S4', 'fixed_display':'19.1R1-S4, 19.1R2'},
  {'min_ver':'19.2',    'fixed_ver':'19.2R1-S1', 'fixed_display':'19.2R1-S1, 19.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set security utm"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
