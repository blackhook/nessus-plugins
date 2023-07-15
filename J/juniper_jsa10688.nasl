#TRUSTED 5147176dd1f1a7bf88b89e271605d8e1ee90811bcb262a97ad4e2de36a1fc053515706d976003d4c65308ef3f55413213a4df72c8527832c55fb385ab8bd9226ff7ddeb27d75f38562ac3987c2e3467595fd097d73613e1f223166c44cd1818b3ae136e6c218c21208406bdc4d7a890a861fcf8dc9c0440c9c4aeacb595ec76e3b55ebb833fbf611ecfce21373cc10f310ba90ba67307429bfb55403ac06eb38c1488bc91059eaf6c6408c2cb79d191b377db923534a883bddf694c5b9bb8b36c0a29affff3546b1b723b0ca6d76d6866968f0007a544d26c03416e049f9835631e898aa358afe0a8ead2cfcd7c4f062587692afe05d357f7647728934f3892337965d2c1f89a4f20bee5aa93b422cc659f64ad8c4ac1edf50362fb9c79d5a85157667e2add67769867d79f1b8833d438f897824d468e4afe26090b2cc9dfba172555052e0dce593f953a1360bf110690c0e9a2c47e4d9a95c6a9d11d763067e9c30f14acf2c16a2735cee0701b3c7d7f6cc48464352062715513778467a0f5b1e23a2e5ce5df8f98a00ce325c1518487083072575d64b5a16b69d3d4ddb98b5ae65675c5338b94629a72a7c591cf39cfb28417a71941015d38b1857537aa1ae0dd6f2f98bae71ca7eb97b31f517318c5eba858e918622aa7fc2b20e6b4be96bc5f504e53717e3f0145dae0e280f6cb6ed9ff8abe0b50d7935063cd6627cecf6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85228);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2015-5360");
  script_bugtraq_id(75720);
  script_xref(name:"JSA", value:"JSA10688");

  script_name(english:"Juniper Junos IPv6 sendd DoS (JSA10688)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability in sendd
due to improper handling of IPv6 Secure Neighbor Discovery (SEND)
Protocol packets when the Secure Neighbor Discovery feature is
configured. A remote attacker, using a crafted SEND packet, can
exploit this to cause excessive consumption of CPU resources,
resulting in an impact on CLI responsiveness and the processing of
IPv6 packets via link-local addresses.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10688");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10688.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['12.1X44'] = '12.1X44-D51';
fixes['12.1X46'] = '12.1X46-D36';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3']    = '12.3R10';
fixes['12.3X48'] = '12.3X48-D20';
fixes['13.2']    = '13.2R8';
fixes['13.3']    = '13.3R6';
fixes['14.1']    = '14.1R5';
fixes['14.2']    = '14.2R3';
fixes['15.1']    = '15.1R1';
fixes['15.1X49'] = '15.1X49-D20';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for neighbor discovery
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols neighbor-discovery secure security-level default";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the Secure Neighbor Discovery feature is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
