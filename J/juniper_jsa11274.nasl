#TRUSTED 2798a9b05eee00b516d9ca536cd2177dbecd87f4d2077faef1d6d621abf003ab483157ad598ccfd46dc94f5d592db9d164ddf2d80a460a62cf1c28c75db6dfabcd290e48f8c75c063caa4180e98172880f27389637cb567e3b6b55c66e5d9a7d629e250d0ab1fd9d67b2f439ff9255a8b151c9ba728e7e9a888cabca962f8a15363d215505b9c5d54b77c5f52dcb165705a88eb9e196905d78d945d7842ebdc0f777fee4e3fa289dc280b42e815f51e1b15afee6fece1cc9c62166ce31fa469609792adbcecdc8a11d0b72253e10ad7187ac1b7664d2e2c9a79139600ce458ff068d09c19cdbb6ab0e2a2bb3b4b538c669ce23f677133ff56a51c9cabbe1a2598012b03b03ba70a852574cae4b1505c5f2351c4d09712b4c8aed3404a0d72fe424906e4b5a5355ee6d0180fdb144c83a0346370b55131194635adc107da14ad5ccf85c5dedb533137e97d68ff5a39bf291caa29c23ef687533521930dd043d0a08e75852f3a141068e70938dd95fa1c17a922865a8104aefc09acb8ad1a448bde61b6341d63809eaecd985778ada7323df3d01357c76350a3c5c56d07ad084bc7c57b22647b639f44b28d623f81d2f1f841aa5bcf638581feefbd57389ffb0210660a5db94ce81844f4df9058541b3598456c6da01810f35d5e741753d13cd9880ce4cee3f383657b10a100a14c1430c93adb8378c0909095a9b0c2d393c8131
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158041);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/15");

  script_cve_id("CVE-2022-22166");
  script_xref(name:"JSA", value:"JSA11274");

  script_name(english:"Juniper Junos OS DoS (JSA11274)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability due to the
routing protocol (rdp) daemon not properly validating data properly in BGP update messages. An unauthenticated, remote
attacker can exploit this, by sending a malformed BGP update message, to cause the rdp daemon to crash.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11274");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11274");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22166");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S1'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2-S2', 'fixed_display':'21.1R2-S2, 21.1R3'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  # Both configurations must exist for it to be vulnerable
  if (!junos_check_config(buf:buf, pattern:"^set protocols bgp.+family.+segment-routing-te") ||
      !junos_check_config(buf:buf, pattern:"^set protocols bgp.+traceoptions flag update"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
