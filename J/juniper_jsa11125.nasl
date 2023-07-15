#TRUSTED 246dd99fd77acf452b6e27db37dc083ff7375f3769bc5ea0d4df12f9031c5e746da888d458fedd641691190fcd3da6b4d1fec005ded233a47e29bf735eed3022a6401f2b202c1c13a5bf45a7bbcf36e0d7f546747f771912269161e39345536d33c310ef3d93d2febe8d7db0d7cb1a4665345eea49e4c5630d414f6a01fd0f3e397720b8449570242b314ed7d7726c5e26fbb616f5fac8e10b68ef64582377951fd8a5aa3471a3aaa70202330d7e5d50c81416473ae0563e9d4a56cbc073a3cf231d4201e7707ca98006bd2daec82069c512d17e4ce88647147d235be4f21c822160f4299bdc8a5558dfedb18e99e79db95c820b8a99349655126453f04126e6c8944edab93c51dda29baeff5f3cbb9de263cb44ab598c9b9fa737362acb8fa88a4ef5e25d4aca38c67c15056ebdea57eda13fc1def01e72796d3cc0aa545d838b7048b5962da241c6f3132ffd566531006bc99086067a7fc67316a7aad415d8dfbd62fc2ff93327119f15633a490199294723315686026fae7d6dfd174f012afcd77063f47ce50a46b30a3b850027b1720b82fe5168970ef4ffe03e3ecb62f422d7976dad561e3b0c07f8aa85256eba83325d0ee539441eaa74ef787466e15bcf66d845c40eb82801d4ccb9fad0392a54320080b18fa753d90e0fb1714380a0fcd6f6ec78f5a02c1640359938943a27f90f09e4c12ab73fe8a443b47b32fa35
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149810);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/21");

  script_cve_id("CVE-2021-0230");
  script_xref(name:"JSA", value:"JSA11125");

  script_name(english:"Juniper Junos OS DoS (JSA11125)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11125
advisory. On Juniper Networks Junos OS platforms with link aggregation (lag) configured, executing any operation that
fetches Aggregated Ethernet (AE) interface statistics, including but not limited to SNMP GET requests, causes a slow
kernel memory leak. If all the available memory is consumed, the traffic will be impacted and a reboot might be
required.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11125");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11125");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0230");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/20");

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

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
var model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

var vuln_ranges = [
  {'min_ver':'17.1R3', 'fixed_ver':'17.3R3-S11'},
  {'min_ver':'17.4',   'fixed_ver':'17.4R3-S5'},
  {'min_ver':'18.2',   'fixed_ver':'18.2R3-S7', 'fixed_display':'18.2R3-S7, 18.2R3-S8'},
  {'min_ver':'18.3',   'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4',   'fixed_ver':'18.4R2-S7'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S6'},
  {'min_ver':'19.1',   'fixed_ver':'19.1R3-S4'},
  {'min_ver':'19.2',   'fixed_ver':'19.2R1-S6'},
  {'min_ver':'19.3',   'fixed_ver':'19.3R3-S1'},
  {'min_ver':'19.4',   'fixed_ver':'19.4R3-S1'},
  {'min_ver':'20.1',   'fixed_ver':'20.1R2',    'fixed_display':'20.1R2, 20.1R3'},
  {'min_ver':'20.2',   'fixed_ver':'20.2R2-S2', 'fixed_display':'20.2R2-S2, 20.2R3'},
  {'min_ver':'20.3',   'fixed_ver':'20.3R1-S2', 'fixed_display':'20.3R1-S2, 20.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  # https://www.juniper.net/documentation/us/en/software/junos/interfaces-ethernet/topics/topic-map/aggregated-ethernet-interfaces-lacp-configure.html
  if (!junos_check_config(buf:buf, pattern:"^set .* gigether-options 802.3ad ae[0-9]+"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
