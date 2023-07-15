#TRUSTED 279ae602b6460a035ca61eea0a3618c12854ead0d1fb15ec0fcb8731f46ea9619d2787c7eacf2ca29f2dfb96878c49df19f379b414e566e30e1d8d6022a3a9e421d36013679d8572f6d787cdafde64062c3a61e1984715517a1d40d9cfe3663a61d685d7b408879b4bb56915c73eedf9fa1bc8406d125df9c746d2c882ca7933706e5b1489b818e3450bb9ba2752deec1df9e6e5dc0168389f80ed676a08b6948b7797d2a825ef13ec6f759f92ca6be82877dbcfdd4f3795d74c1f7975ffb185902e2f30a25f62bab289774006cbeae5842bc2896c7b9f258b473d9ba649ddce16f99a2a7a3525dd1e24fb49fe4e688e461162027b5c33f610bd8e2b7464ef69d14340240d996efefde48381c132c715501533e34173ad9520b09656d0f9444f927ffe89960c9dc962d4f3a73e53c1d4a5f2f27112abc11b05142e0460504ad0cf199dc22e5542abbe08ddc9d45a92026d7b464cd472c52565d9401baf8abe64c8d5f8b6a2ac62183b4ac60e09016f3c5c4bce187c6eeeabb29b423ba38f9269b227847756cfa6ba8bace86e69d83aeff9093d79042cbbaccc5b4e29b0dc75ac5863d70fbcb7b7def3f3a243740eb96b283d9836673f8262f490c73993b592cd44c80fe312d42f23c18cfc9f6cd01967d6f38e468a6a3603718704d1161ef64b5a37f826798c8b29c722525269558c085640128c847005ba63fe135c275aa33e
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148650);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/02");

  script_cve_id("CVE-2021-0259");
  script_xref(name:"JSA", value:"JSA11150");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11150)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11150
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11150");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11150");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0259");

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
if (model !~ "^QFX(5[0-9]{3}([^0-9]|$)|5K)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.3',   'fixed_ver':'17.3R3-S11'},
  {'min_ver':'17.4',   'fixed_ver':'17.4R3-S5'},
  {'min_ver':'18.1',   'fixed_ver':'18.1R3-S13'},
  {'min_ver':'18.2',   'fixed_ver':'18.2R2-S8'},
  {'min_ver':'18.2R3', 'fixed_ver':'18.2R3-S8'},
  {'min_ver':'18.3',   'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4',   'fixed_ver':'18.4R1-S8'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R2-S6'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S6'},
  {'min_ver':'19.1',   'fixed_ver':'19.1R3-S4'},
  {'min_ver':'19.2',   'fixed_ver':'19.2R1-S6'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S2'},
  {'min_ver':'19.3',   'fixed_ver':'19.3R3-S2'},
  {'min_ver':'19.4',   'fixed_ver':'19.4R2-S4'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S1'},
  {'min_ver':'20.1',   'fixed_ver':'20.1R2'},
  {'min_ver':'20.2',   'fixed_ver':'20.2R2'},
  {'min_ver':'20.3',   'fixed_ver':'20.3R1-S2', 'fixed_display':'20.3R1-S2, 20.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
# https://www.juniper.net/documentation/us/en/software/junos/evpn-vxlan/topics/task/evpn-routing-instance-vlan-based-configuring.html
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set routing-instances .* vxlan vni [0-9]+"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
