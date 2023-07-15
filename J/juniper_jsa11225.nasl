#TRUSTED 5411cbfe08a02b3d7bbcd6000d15722a173772611eb8bc366237a2b63d8fa55cfdf6fe3eaebe25357539862f1699b7c5b29c1c70af7420aa9360318d7d98f73d898f3fe131305c7e359f210f720c58567edcc5eb5a6e13cda55651c92fabc0c8bd75c3fc2d9f9925fef5c75b24c873dde9b960e674824f6a6967ee73636118ed8fc2002f2b29054eee86feaa1e5b3d85054fc027a9a21dc763cd13c832b7f40694cdcd824ead6523156a71c1a11a74f42b92860ecd72b915c60adabe0427e81391242d598cf80ece5e25f7093042bad00b94ab1d7ff06089d0dfd1d7b4f14ba464b949aec8bbef9ff8706cfb119552e0902bf096a2c57bebb15c353aef608a350b8851ce5ce6a1b092c65c995405121b6209c22e08be17336767f290c001d5b40b4df1b362ffe298f511829f04d58c08d9122063282c355d95f01f33afcde4ef9a42089595203c0cd4e4c2043f5f4f28c45ce70367681492f6501e9c6a9ad2bb2dc7331e00defb41f2963050e4bc35c5075a86fd5bf0697c81a72be7a270b7d56b720a15952b78218a81abf55139d5eb25f2c2d28257b00f860ce74abbbf142ad4a7ce9ffe855b4f59afce8486f7edcb33306361735ba55ccea6810cadf743d957edf72f80e40d796e602aa0016e8632e097cdeeab520673a441fde8bed7072248efd7cd36474051bcf8c077d28a92408fe362864fb49aee3b0da48b804c420f
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154118);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/15");

  script_cve_id("CVE-2021-31363");
  script_xref(name:"JSA", value:"JSA11225");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11225)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11225
advisory.

  - In an MPLS P2MP environment a Loop with Unreachable Exit Condition vulnerability in the routing protocol
    daemon (RPD) of Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated adjacent attacker
    to cause high load on RPD which in turn may lead to routing protocol flaps. If a system with sensor-based-
    stats enabled receives a specific LDP FEC this can lead to the above condition. Continued receipted of
    such an LDP FEC will create a sustained Denial of Service (DoS) condition. This issue affects: Juniper
    Networks Junos OS 19.2 version 19.2R2 and later versions prior to 19.2R3-S3; 19.3 versions prior to
    19.3R2-S6, 19.3R3-S2; 19.4 versions prior to 19.4R1-S4, 19.4R2-S4, 19.4R3-S2; 20.1 versions prior to
    20.1R2-S1, 20.1R3; 20.2 versions prior to 20.2R2-S1, 20.2R3; 20.3 versions prior to 20.3R1-S2, 20.3R2.
    This issue does not affect Juniper Networks Junos OS versions prior to 19.2R2. Juniper Networks Junos OS
    Evolved All versions prior to 20.1R2-S3-EVO; 20.3 versions prior to 20.3R1-S2-EVO. (CVE-2021-31363)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11225");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11225");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31363");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'19.2', 'fixed_ver':'19.2R2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S2'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S4'},
  {'min_ver':'19.4R2', 'fixed_ver':'19.4R2-S4'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S2'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S1', 'fixed_display':'20.1R2-S1, 20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S1', 'fixed_display':'20.2R2-S1, 20.2R3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1-S2', 'fixed_display':'20.3R1-S2, 20.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!(preg(string:buf, pattern:"^set protocols ldp traffic-statistics", multiline:TRUE)) ||
      !(preg(string:buf, pattern:"^set protocols ldp p2mp", multiline:TRUE))
      )
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
