#TRUSTED 17321c3d2192f4d60db25fb1b161972d11285d5ae114abf416f4aef8872414e81195822b0727a72fef9aaa4c656014876c2f60fd0ad7d0f7d8353c8d537fe77b0833ad7604b713dec3532c05964f62ed0d944d7c064bf62da40e5f5b36c4174f3579f21514eb9c4b3ec639ef5fbaef9ae7b99f71a12e79d61811519581a51db030d226ec64869de0cc3fbfd3f3a24e75a86bdb9f130b367bf1447b232aaa51f2b162641f0985649df8f287285dcffed1b6e65e999a768c51d59e4f613b157a4a084c70fb0ada6eb13ef222a4ee413223dd84752a10ee07835b34ab424a9503a0282d81b947a7a1d1eb5b0f000c64b7f76295924f50fb6b3db122160bd636803ce59eba17fad40f245eaa40ac702572f925776411db15d062fae4108688a6a6bdedb818721a9f6a9926fff27f71fc6cdac5f3e4a211b30d4661234cb1a8a819aabf558aa29efb1632550bfad21ff78b3cfd8dd30171fbb437f3ca03f3397a09818f6b67630177675939caabe3652d64553bc2c526675e79bcae99827d8fb0c49a659797ee3fb60860aa747c147fdf02545638b733ae965df6032c62bb114f091d4af1dcda5784c03851777c97b3faf6db05f54ec109a8847718308fbe684d5fa513afa94819601cf0abc2a1ee3821b6a9354f471178d819cd4069ba1fe45c692ceff699ef501dc7e7d992704e05956d7b6dd006010c6ad8098952c09591c2dbf1
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-nat.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70320);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-5479", "CVE-2013-5480", "CVE-2013-5481");
  script_bugtraq_id(62637, 62639, 62641);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtn53730");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq14817");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf28733");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-nat");

  script_name(english:"Cisco IOS Software Network Address Translation Vulnerabilities (cisco-sa-20130925-nat)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS Software implementation of the network address
translation (NAT) feature contains three vulnerabilities when
translating IP packets that could allow an unauthenticated, remote
attacker to cause a denial of service (DoS) condition. Cisco has
released free software updates that address these vulnerabilities.
Workarounds that mitigate these vulnerabilities are not available."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-nat
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bdf7d81"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130925-nat."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

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
if ( version == '12.2(33)SXI7' ) flag++;
if ( version == '12.2(33)SXJ1' ) flag++;
if ( version == '12.2(50)SY3' ) flag++;
if ( version == '12.2(50)SY4' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)M6a' ) flag++;
if ( version == '15.0(1)M7' ) flag++;
if ( version == '15.0(1)SY' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(3)T3' ) flag++;
if ( version == '15.1(3)T4' ) flag++;
if ( version == '15.1(4)GC' ) flag++;
if ( version == '15.1(4)GC1' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)M5' ) flag++;
if ( version == '15.1(4)M6' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;
if ( version == '15.1(4)XB5a' ) flag++;
if ( version == '15.1(4)XB6' ) flag++;
if ( version == '15.1(4)XB7' ) flag++;
if ( version == '15.1(4)XB8a' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(1)T2' ) flag++;
if ( version == '15.2(1)T3' ) flag++;
if ( version == '15.2(1)T3a' ) flag++;
if ( version == '15.2(1)T4' ) flag++;
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(2)JA' ) flag++;
if ( version == '15.2(2)JA1' ) flag++;
if ( version == '15.2(2)JAX' ) flag++;
if ( version == '15.2(2)JB' ) flag++;
if ( version == '15.2(2)JB1' ) flag++;
if ( version == '15.2(2)T' ) flag++;
if ( version == '15.2(2)T1' ) flag++;
if ( version == '15.2(2)T2' ) flag++;
if ( version == '15.2(2)T3' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GC1' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)T2' ) flag++;
if ( version == '15.2(3)T3' ) flag++;
if ( version == '15.2(3)XA' ) flag++;
if ( version == '15.2(4)JA' ) flag++;
if ( version == '15.2(4)M' ) flag++;
if ( version == '15.2(4)M1' ) flag++;
if ( version == '15.2(4)M2' ) flag++;
if ( version == '15.2(4)M3' ) flag++;
if ( version == '15.2(4)XB10' ) flag++;
if ( version == '15.3(1)T' ) flag++;
if ( version == '15.3(1)T1' ) flag++;
if ( version == '15.3(2)T' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\s+ip\s+nat\s+[eio]", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
