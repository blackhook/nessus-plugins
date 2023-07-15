#TRUSTED 6c462859ce45b791657016c4ba4631f2b7cf2d8dc9a541615b7359cc288b79329972fb967272cd6940821ef91278383720a5045b218c66316d40ebffa4f63390beb64c7e8843e071b85c5331dafdbeba3ca58d7628378098ebe855ddea621abf607ce0c8279d623ca9957e2ba362838e00ef52694e9c4036a4a71dc9c69abfc3ca3afdb6bedde5f1065558f764d04c4adfa83d90564d1a16c02e53fe1cd67bed65b0111fe36be44137fa0fea43a31a15a8974f579e74924ea1b5cc92c836ec5b8aed8be28d984fe669775df9778a279e4b3d734efd8bd2dbb6aea39af261b00acc8d0df22d7796b6820506fa52ec0db6eaf71179ae7391913711e666aca59f220c913f85e0b51cb48f29c405158a21df9fbc781820d95e681e448673eb5928445ef5225f4577157bc6db2661105e780a525616b5130468450f1a955be6e8304cdeab58c1a2d1a3ae71a0d62915b0789fb60a90bf826d77731440071c1f1cfef8baa8203455f2a975e113beaae7ffd98c9113a653d002f6c34eabfde69ad2ebdd0df1d6ae697a797223b25913f75458c769f39901b27cc174837e48f41f898a104692030a9eeb1720076f55b85bfbf619895438f70b7e3d5f5b2392a27c28dc7703effa19f6737f9d6a1c88db0fd6a24b5d191a74a4b11e8c16183ec3ff8e7d2fca4246f95e753af9bbf670146658079c53c593b6bf74842a22fa23f2f739b4b8
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153128);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/09");

  script_cve_id("CVE-2021-0285");
  script_xref(name:"JSA", value:"JSA11187");

  script_name(english:"Juniper Junos OS DoS (JSA11187)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11187
advisory.

  - An uncontrolled resource consumption vulnerability in Juniper Networks Junos OS on QFX5000 Series and
    EX4600 Series switches allows an attacker, which is sending large amounts of legitimate traffic destined
    to the device, to cause Interchassis Control Protocol (ICCP) interruptions leading to an unstable control
    connection between the MC-LAG nodes which can in turn lead to traffic loss. (CVE-2021-0285)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11187");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11187");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0285");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

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
if (model !~ "^(EX46|QFX5)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S9'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S11'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S13'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S5'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S8'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S7'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S5'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S6'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S2'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S4'},
  {'min_ver':'19.4R2', 'fixed_ver':'19.4R2-S4'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S2'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2', 'fixed_display':'20.1R2-S2, 20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S3', 'fixed_display':'20.2R2-S3, 20.2R3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R1-S1', 'fixed_display':'20.4R1-S1, 20.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"set protocols iccp peer.*", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
