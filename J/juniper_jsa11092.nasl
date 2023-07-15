#TRUSTED 86032184ca66c1677452d9d6e7a62f224a7edb2d45eca2a9ac6ff37768150170d6640bc29bfbb982e8c94f05ff7eb3e6a57b6bc3e0fde6ff3269604d21f7162f4b165c6438519d7778fd5bb24f54f04cfca421220191c44d8aaa6128df8c9b1fb1f3f84fed6abdcd0943246d45d0ad3005aa4dd5261c8299c83850a13d02d41fbc7e2742a742528c40d599ee463cf5ad0789df8321a92e80991d57addadaa77e3ee1f39ccfa23904f84ca80d408ca1eb27f2f8dc2c783339206e2570f7d76f3767ba4e585b7575f81ee889b394e1bc8cabd50161a63ea14bfade0a0d6f355bae6132fc0e72076b95767d5ea26f11b55a1a8c9bab7b1302fa9fefeb467e11b713b513a7f09cd900b4dd6cee418235c509a4ecf09acc370625cd9a48c85095aa94a8c582af6cb0f6055f30dc7bf45f1c046224e9d149c3fcd10ef5ddb8645004ebe416eb26c94ca75d4f874ebd89d07b0de42eb0e6c22e427c918a9151525f4c5a11677919541e33ea4f424c80b6daef514dd91a304c828ccab8e1c688823da6368e17c5448f7ed43d8f137208f0fdca4916309071abdd4d368a7869aadcfb1baf72912e3dcc96e742577182f951304e09b7c1ed52c863bdb905abf82c5125263f5032684db30f5b5556bf087c3ff1d9f3c4e2377bb3ecd38b3eb018ddf46885f8cb06d1bd14d9940568069745f325c683dc6148c020cfff9841da27bcb3bd1c81
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144986);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");

  script_cve_id("CVE-2021-0202");
  script_xref(name:"JSA", value:"JSA11092");

  script_name(english:"Juniper Junos OS DoS (JSA11092)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced in 
the JSA11092 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11092");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11092");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0202");

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
if (model !~ "^(EX92|MX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'17.3R3-S8', 'fixed_ver':'17.3R3-S9'},
  {'min_ver':'17.4R3-S2', 'fixed_ver':'17.4R3-S3'},
  {'min_ver':'18.2R3-S4', 'fixed_ver':'18.2R3-S6'},
  {'min_ver':'18.3R3-S2', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4R3-S1', 'fixed_ver':'18.4R3-S6'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S1'},
  {'min_ver':'19.4R2', 'fixed_ver':'19.4R2-S3'},
  {'min_ver':'20.2R1', 'fixed_ver':'20.2R1-S3'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

#set routing-instances r1 instance-type vpls
#set bridge-domains bd1 bridge-options interface ge-4/0/6.0 interface-mac-limit 131071
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;

  #bridge domains
  if (junos_check_config(buf:buf, pattern:"^set bridge-domains.*routing-interface irb\..*") &&
    junos_check_config(buf:buf, pattern:"^set bridge-domains.*domain-type bridge"))
      junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

  #vlps
  else if (junos_check_config(buf:buf, pattern:"^set routing-instances.*instance-type vpls") &&
    junos_check_config(buf:buf, pattern:"^set routing-instances.*routing-interface irb\..*"))
      junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
}
audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
