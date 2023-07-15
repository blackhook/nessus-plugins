#TRUSTED 865c97c7c1bf0049a63700e960d4bfe2f37dd21e3d79bec9f4576e17121de2cca58bb3cfa3e52ee89815337cf4164be2287d248c7b6be39ba548af92301f53d2e21d9e4ca792947e0970570e0fd415f7b5478cbd4fb2ab8b6f0b99e7c4adf8bb2a12e2bc3e009eb79940ff7425e71d40d5aaf81197e63524d0ff6a943751f759bdd32c4139b1669c6c1c64d79b18abadf0eed8b51a846154d981392d3daebbc253308520468d06582178190027dd0d5c28759d9ef193b472d34c1bfe5ff070f16d36fa7c3aaeadef8bafd7a68f9454c8e5b27c1285c87ad2c984913866e447ade7ddf311e110369924e395fb232165ba5dd165b405a1334e930b1dcf51c23a851aabcfd1e4c3e5a2ad1f27b15d86c828f4fb2e74a8f74e94275f7ae5fa50b8dada5d2b380a8f6265770c8f523c18ca1e804e47fa3b157f549c33cc63f28282c63135f8f0e90206b8e4a01b710a3e6073145f4bae82cbf9fef2a5edce0af3e21deaa84869d9c0beed65f53d36d74982081f77af32810ed7cad07951f7fdab101c8c46634d44ef0e66c8631bb40c0552a4144dfa65527645307ec87c1f1a86c167f5dde3f93c286e8212a5b2cb7ec8b1c08acb7e1e3662569eb47e31f6bfed443291179d9b0a7ca29788ae65e9855e566a8079485c722b2be719210e0093041ef7263d53bbadf4cddc767e2c5f8b882d5c95d2c0b09563603d340e77e3639b5028
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145261);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2021-0206");
  script_xref(name:"JSA", value:"JSA11096");
  script_xref(name:"IAVA", value:"2021-A-0036-S");

  script_name(english:"Juniper Junos DoS (JSA11096)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11096
advisory. A NULL Pointer Dereference vulnerability in Juniper Networks Junos OS allows an attacker to send a specific
packet causing the packet forwarding engine (PFE) to crash and restart, resulting in a Denial of Service (DoS). By
continuously sending these specific packets, an attacker can repeatedly disable the PFE causing a sustained Denial of
Service (DoS). This issue only affects Juniper Networks NFX Series, SRX Series platforms when SSL Proxy is configured.
This issue affects Juniper Networks Junos OS on NFX Series and SRX Series: 18.3 versions prior to 18.3R3-S4; 18.4
versions prior to 18.4R3-S1; 19.1 versions prior to 19.1R1-S6, 19.1R2-S2, 19.1R3; 19.2 versions prior to 19.2R1-S2,
19.2R2; 19.3 versions prior to 19.3R2. This issue does not affect Juniper Networks Junos OS versions on NFX Series and
SRX Series prior to 18.3R1.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11096");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11096");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0206");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (model !~ "^(NFX|SRX)")
  audit(AUDIT_DEVICE_NOT_VULN, model);

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S1'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S6', 'fixed_display': '19.1R1-S6 / 19.1R2-S2 / 19.1R3'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R2-S2', 'fixed_display':'19.1R2-S2 / 19.1R3'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S2', 'fixed_display':'19.2R1-S2 / 19.2R2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2'}
];

override = TRUE;
# https://www.juniper.net/documentation/en_US/junos/topics/topic-map/security-ssl-proxy-forward-reverse-proxy.html
# We can look in the set config for this
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set services ssl proxy", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
