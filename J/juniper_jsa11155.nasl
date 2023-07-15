#TRUSTED 67519a5c4db83481b56f26cfa10a62dd461d8102263757130567acd76c2ab74923902c7eb0ff7324a36e0f3c842b824fd56bcf477bb0cd53d31d3698aea4248149277f8bab8e13d800d873657b010aa6daf4f6ed1c930b82154da96541d901fcf48f29dc5b9bb8188414ca94d4f1fafafd695a128cb479d489744a8801567e5df8fab89c67b8ef63f3e2ec3d1b7c8b5cd3f14bf8bb6821ca6e682da1f36730c3d6d728323ea0a6ff6d1db0a56fb02fc2bf90d1e2554a8ad1c21fc1cc55d5f618c8e286928a5c621f0dc9f2934ad76751af9ef5df8c953fcd2d0ff53c134888cd556dff3c84782f3836561693a79bf4009ad12ceced291c5835ee07d75eb0ba02f09def1f7f54b4ae2f2101021704c347c8c157efd256b5aa93772f8138e9da9292503947f0a140a495a3387072a7468012acd83caa35e88404f4afc92e9006a5447bff4ff2ebec77db477039d7e26e522e0e2139b5780157a425e42eb08af83c6956625ff377f664a04072258e941732c5a93a3fb47b4848a73e425d312c9e5b8ba796066bc167892a659b1295a73dda16c807c4b0f7e96e01740f7708b686e07a2145c17c424dc99150b9a5773ecd739960659f9c48bbcc1d88c432b97df29d0bf8490472bd09c7c91cbcca34bf3ac3e17dafb7032c50d0dcf7fbf9a544cfd9690668e6e5faa9505ef7602df78089d9211ec585af244abcd3630ebc9c2aa71d
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148669);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/02");

  script_cve_id("CVE-2021-0264");
  script_xref(name:"JSA", value:"JSA11155");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11155)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11155
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11155");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11155");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0264");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

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
if (model !~ "^v?MX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S2'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S2'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S2', 'fixed_display':'20.2R2-S2, 20.2R3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

# MPC10/11 check
var override = TRUE;
var buf = junos_command_kb_item(cmd:'show chassis hardware models');
if (buf)
{
  override = FALSE;
  if (buf !~ "MPC1[01]")
    audit(AUDIT_HOST_NOT, 'using an affected MPC card');
}

# Config check
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set firewall .* term .* then syslog"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
