#TRUSTED 39b177d73e16a04a3e73f515b043b7a65ddf2cd031acfa3ec39c25d1eb8c1da1f2674d027d6561bb6035730c63d05c54c5b39f17681982e926ee3d52ee48cd11fbec05f9a02770c1bc4d37dfb2a41dca88d79d03e9565349f913f4848c59d8afec001ff62be1ea593262be2b6c24ab0802555d946fbbdd231677c5ea12d193c24455809f06320923c5544cfc08c3143d84b97dc7f3483b19ebbd291ff3c492f3fecbcbab5bb887f01d07b431fd0a19c0a89425f58de7daa0e8db37979a8ce28a8e40b5a86480bfc8f5d9df5d0518cf5c2b88d655fb0bc362b29550cc5ef990f0bac8373d27cf89de560fcaf5876a4fd68cfa1ce965e2959de553d9d304fbdd60ae60b25c58c81177c351ac5b7572d870cb1b3cba48d6c4d7f07738a78140b2407302f7f3151f32764813c245191a9aec237e9e643a07dc98c7cc05fac57bcd0d0acc2b40bb948ed680d6cdaf9f1dbe77492d523287a527c5307945c2078a9345811d483b12e6a34395df7c813da66145e34c83822cf405c3035f380338bc0766c06070a9761fc311894b103a7c3dc7244b53002b27f72dce06ec7b84e9e7007bf66c61cecf2aebe0a8c0037a79a735c6fd603dec8f4c1be5abda38954d198a368c81e960724826939e6d15bff6cb9c62f7921f8b36b868e6c6115fff82f13811d9d8b200009b208da518f5f5bc64251ace7bc1068ef6dbdb380eb38d848d1311
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130327-cce.
# The text itself is copyright (C) Cisco
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(65885);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-1145");
  script_bugtraq_id(58741);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtl99174");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130327-cce");

  script_name(english:"Cisco IOS Software Zone-Based Policy Firewall Session Initiation Protocol Inspection Denial of Service Vulnerability (cisco-sa-20130327-cce)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a memory leak vulnerability that could be
triggered through the processing of malformed Session Initiation
Protocol (SIP) messages. Exploitation of this vulnerability could
cause an interruption of services. Only devices that are configured
for SIP inspection are affected by this vulnerability. Cisco has
released free software updates that address this vulnerability. There
are no workarounds for devices that must run SIP inspection."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130327-cce
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a6af1ed"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130327-cce."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '12.4(15)XZ' ) flag++;
if ( version == '12.4(15)XZ1' ) flag++;
if ( version == '12.4(15)XZ2' ) flag++;
if ( version == '12.4(20)MR' ) flag++;
if ( version == '12.4(20)MR2' ) flag++;
if ( version == '12.4(20)MRA' ) flag++;
if ( version == '12.4(20)MRA1' ) flag++;
if ( version == '12.4(20)MRB' ) flag++;
if ( version == '12.4(20)MRB1' ) flag++;
if ( version == '12.4(20)T' ) flag++;
if ( version == '12.4(20)T1' ) flag++;
if ( version == '12.4(20)T2' ) flag++;
if ( version == '12.4(20)T3' ) flag++;
if ( version == '12.4(20)T4' ) flag++;
if ( version == '12.4(20)T5' ) flag++;
if ( version == '12.4(20)T5a' ) flag++;
if ( version == '12.4(20)T6' ) flag++;
if ( version == '12.4(20)YA' ) flag++;
if ( version == '12.4(20)YA1' ) flag++;
if ( version == '12.4(20)YA2' ) flag++;
if ( version == '12.4(20)YA3' ) flag++;
if ( version == '12.4(22)GC1' ) flag++;
if ( version == '12.4(22)GC1a' ) flag++;
if ( version == '12.4(22)MD' ) flag++;
if ( version == '12.4(22)MD1' ) flag++;
if ( version == '12.4(22)MD2' ) flag++;
if ( version == '12.4(22)MDA' ) flag++;
if ( version == '12.4(22)MDA1' ) flag++;
if ( version == '12.4(22)MDA2' ) flag++;
if ( version == '12.4(22)MDA3' ) flag++;
if ( version == '12.4(22)MDA4' ) flag++;
if ( version == '12.4(22)MDA5' ) flag++;
if ( version == '12.4(22)MDA6' ) flag++;
if ( version == '12.4(22)T' ) flag++;
if ( version == '12.4(22)T1' ) flag++;
if ( version == '12.4(22)T2' ) flag++;
if ( version == '12.4(22)T3' ) flag++;
if ( version == '12.4(22)T4' ) flag++;
if ( version == '12.4(22)T5' ) flag++;
if ( version == '12.4(22)XR' ) flag++;
if ( version == '12.4(22)XR1' ) flag++;
if ( version == '12.4(22)XR10' ) flag++;
if ( version == '12.4(22)XR11' ) flag++;
if ( version == '12.4(22)XR12' ) flag++;
if ( version == '12.4(22)XR2' ) flag++;
if ( version == '12.4(22)XR3' ) flag++;
if ( version == '12.4(22)XR4' ) flag++;
if ( version == '12.4(22)XR5' ) flag++;
if ( version == '12.4(22)XR6' ) flag++;
if ( version == '12.4(22)XR7' ) flag++;
if ( version == '12.4(22)XR8' ) flag++;
if ( version == '12.4(22)XR9' ) flag++;
if ( version == '12.4(22)YB' ) flag++;
if ( version == '12.4(22)YB1' ) flag++;
if ( version == '12.4(22)YB4' ) flag++;
if ( version == '12.4(22)YB5' ) flag++;
if ( version == '12.4(22)YB6' ) flag++;
if ( version == '12.4(22)YB7' ) flag++;
if ( version == '12.4(22)YB8' ) flag++;
if ( version == '12.4(22)YD' ) flag++;
if ( version == '12.4(22)YD1' ) flag++;
if ( version == '12.4(22)YD2' ) flag++;
if ( version == '12.4(22)YD3' ) flag++;
if ( version == '12.4(22)YD4' ) flag++;
if ( version == '12.4(22)YE' ) flag++;
if ( version == '12.4(22)YE1' ) flag++;
if ( version == '12.4(22)YE2' ) flag++;
if ( version == '12.4(22)YE3' ) flag++;
if ( version == '12.4(22)YE4' ) flag++;
if ( version == '12.4(22)YE5' ) flag++;
if ( version == '12.4(22)YE6' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)GC3' ) flag++;
if ( version == '12.4(24)GC3a' ) flag++;
if ( version == '12.4(24)GC4' ) flag++;
if ( version == '12.4(24)GC5' ) flag++;
if ( version == '12.4(24)MD' ) flag++;
if ( version == '12.4(24)MD1' ) flag++;
if ( version == '12.4(24)MD2' ) flag++;
if ( version == '12.4(24)MD3' ) flag++;
if ( version == '12.4(24)MD4' ) flag++;
if ( version == '12.4(24)MD5' ) flag++;
if ( version == '12.4(24)MD6' ) flag++;
if ( version == '12.4(24)MD7' ) flag++;
if ( version == '12.4(24)MDA' ) flag++;
if ( version == '12.4(24)MDA1' ) flag++;
if ( version == '12.4(24)MDA10' ) flag++;
if ( version == '12.4(24)MDA11' ) flag++;
if ( version == '12.4(24)MDA12' ) flag++;
if ( version == '12.4(24)MDA13' ) flag++;
if ( version == '12.4(24)MDA2' ) flag++;
if ( version == '12.4(24)MDA3' ) flag++;
if ( version == '12.4(24)MDA4' ) flag++;
if ( version == '12.4(24)MDA5' ) flag++;
if ( version == '12.4(24)MDA6' ) flag++;
if ( version == '12.4(24)MDA7' ) flag++;
if ( version == '12.4(24)MDA8' ) flag++;
if ( version == '12.4(24)MDA9' ) flag++;
if ( version == '12.4(24)MDB' ) flag++;
if ( version == '12.4(24)MDB1' ) flag++;
if ( version == '12.4(24)MDB10' ) flag++;
if ( version == '12.4(24)MDB11' ) flag++;
if ( version == '12.4(24)MDB12' ) flag++;
if ( version == '12.4(24)MDB3' ) flag++;
if ( version == '12.4(24)MDB4' ) flag++;
if ( version == '12.4(24)MDB5' ) flag++;
if ( version == '12.4(24)MDB5a' ) flag++;
if ( version == '12.4(24)MDB6' ) flag++;
if ( version == '12.4(24)MDB7' ) flag++;
if ( version == '12.4(24)MDB8' ) flag++;
if ( version == '12.4(24)MDB9' ) flag++;
if ( version == '12.4(24)MDC' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(24)T31f' ) flag++;
if ( version == '12.4(24)T32f' ) flag++;
if ( version == '12.4(24)T33f' ) flag++;
if ( version == '12.4(24)T34f' ) flag++;
if ( version == '12.4(24)T35c' ) flag++;
if ( version == '12.4(24)T35f' ) flag++;
if ( version == '12.4(24)T36f' ) flag++;
if ( version == '12.4(24)T3c' ) flag++;
if ( version == '12.4(24)T3e' ) flag++;
if ( version == '12.4(24)T3f' ) flag++;
if ( version == '12.4(24)T3g' ) flag++;
if ( version == '12.4(24)T4' ) flag++;
if ( version == '12.4(24)T4a' ) flag++;
if ( version == '12.4(24)T4b' ) flag++;
if ( version == '12.4(24)T4c' ) flag++;
if ( version == '12.4(24)T4d' ) flag++;
if ( version == '12.4(24)T4e' ) flag++;
if ( version == '12.4(24)T4f' ) flag++;
if ( version == '12.4(24)T4g' ) flag++;
if ( version == '12.4(24)T4h' ) flag++;
if ( version == '12.4(24)T4i' ) flag++;
if ( version == '12.4(24)T4j' ) flag++;
if ( version == '12.4(24)T5' ) flag++;
if ( version == '12.4(24)T6' ) flag++;
if ( version == '12.4(24)T7' ) flag++;
if ( version == '12.4(24)T8' ) flag++;
if ( version == '12.4(24)YE' ) flag++;
if ( version == '12.4(24)YE1' ) flag++;
if ( version == '12.4(24)YE2' ) flag++;
if ( version == '12.4(24)YE3' ) flag++;
if ( version == '12.4(24)YE3a' ) flag++;
if ( version == '12.4(24)YE3b' ) flag++;
if ( version == '12.4(24)YE3c' ) flag++;
if ( version == '12.4(24)YE3d' ) flag++;
if ( version == '12.4(24)YE4' ) flag++;
if ( version == '12.4(24)YE5' ) flag++;
if ( version == '12.4(24)YE6' ) flag++;
if ( version == '12.4(24)YE7' ) flag++;
if ( version == '12.4(24)YG1' ) flag++;
if ( version == '12.4(24)YG2' ) flag++;
if ( version == '12.4(24)YG3' ) flag++;
if ( version == '12.4(24)YG4' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)M6a' ) flag++;
if ( version == '15.0(1)M7' ) flag++;
if ( version == '15.0(1)M8' ) flag++;
if ( version == '15.0(1)M9' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;
if ( version == '15.0(1)XA5' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)T4' ) flag++;
if ( version == '15.1(1)T5' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)GC2' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(2)T5' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(3)T3' ) flag++;
if ( version == '15.1(3)T4' ) flag++;
if ( version == '15.1(4)GC' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)M5' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;
if ( version == '15.1(4)XB5a' ) flag++;
if ( version == '15.1(4)XB6' ) flag++;
if ( version == '15.1(4)XB7' ) flag++;
if ( version == '15.1(4)XB8a' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map_type_inspect_zone-pair", "show policy-map type inspect zone-pair");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Match:\s+[Pp]rotocol sip", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
