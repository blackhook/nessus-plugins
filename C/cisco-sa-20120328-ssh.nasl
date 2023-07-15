#TRUSTED 39fc27422f4dc5205a300a7362bb0a5bae2be47941e1830db2faf74a76e923777334225c89b1fc7b431a4c29b41c24898cfb2ce67ae0631bf50771ac32b3d72cb5b62fe939e3b31b09debcf55e2a3e45e86de56443cb1bbae885cbe7dfbccad5ccd8ed0d62afba9b25b275aa5aaaad89644722c98a83b02dbd35831b320edef62ac8b2dffc3321b88a7da8ecb22b89fcecdf7f86c0b09a868dbb81920f8d462b9a7d2fd1db909e71bd83440763df8c373b9a3a8d47c4dced0aa8976e89ee6e0fa3c3a88df0f63f39c7b782e39d133565af8255d1ddf8eff5f0c36281f0f1c58611f2e954d2eed41949c2d8fe43feddab5c272c2f7d218be3a06e04a3f1f1da026e6f41ec915dd135695476a871095dbf1cc85f1823b7df3e11f70eef16a81939773c21560106afb1dcbbfec451a36e5b4a776e096f00671f7de82347e14ce95d99c4dbeea99a877217e9cedcdd40ae280ba6f930f874f4db00fde1a8e7345386b1ba89331b9579dede1a87695277644c3b2af6afd84d6838063b50c34f332e3ec1a98a224befa2af6a6b2c67e4a7bd6b901627bd4e5af6434d2f5b19a9131a86bf9f87cdc28bc8b6558c7bb923b21a4fe5204d9406e9c99582d2dacd6f7be9ebeaecfc8e746e4410be869708e8c0325d8b605c607069db4ab46fa33e5cf75ba36448195181e6cb0b218fc7c20725173e487acad2c1fa9f9dcc7cc93443a23303
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120328-ssh.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(58573);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2012-0386");
  script_bugtraq_id(52752);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtr49064");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120328-ssh");

  script_name(english:"Cisco IOS Software Reverse SSH Denial of Service Vulnerability (cisco-sa-20120328-ssh)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Secure Shell (SSH) server implementation in Cisco IOS Software and
Cisco IOS XE Software contains a denial of service (DoS) vulnerability
in the SSH version 2 (SSHv2) feature. An unauthenticated, remote
attacker could exploit this vulnerability by attempting a reverse SSH
login with a crafted username. Successful exploitation of this
vulnerability could allow an attacker to create a DoS condition by
causing the device to reload. Repeated exploits could create a
sustained DoS condition. The SSH server in Cisco IOS Software and
Cisco IOS XE Software is an optional service, but its use is highly
recommended as a security best practice for the management of Cisco
IOS devices. Devices that are not configured to accept SSHv2
connections are not affected by this vulnerability. Cisco has released
free software updates that address this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120328-ssh
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8f7d4cf"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120328-ssh."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");
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
if ( version == '12.2(33)XNC' ) flag++;
if ( version == '12.2(33)XNC0b' ) flag++;
if ( version == '12.2(33)XNC0c' ) flag++;
if ( version == '12.2(33)XNC0e' ) flag++;
if ( version == '12.2(33)XNC1' ) flag++;
if ( version == '12.2(33)XNC2' ) flag++;
if ( version == '12.2(33)XND' ) flag++;
if ( version == '12.2(33)XND1' ) flag++;
if ( version == '12.2(33)XND2' ) flag++;
if ( version == '12.2(33)XND2t' ) flag++;
if ( version == '12.2(33)XND3' ) flag++;
if ( version == '12.2(33)XND4' ) flag++;
if ( version == '12.2(33)XNE' ) flag++;
if ( version == '12.2(33)XNE1' ) flag++;
if ( version == '12.2(33)XNE1xb' ) flag++;
if ( version == '12.2(33)XNE2' ) flag++;
if ( version == '12.2(33)XNE3' ) flag++;
if ( version == '12.2(33)XNF' ) flag++;
if ( version == '12.2(33)XNF1' ) flag++;
if ( version == '12.2(33)XNF2' ) flag++;
if ( version == '12.2(58)EY' ) flag++;
if ( version == '12.2(58)EY1' ) flag++;
if ( version == '12.2(58)SE2' ) flag++;
if ( version == '12.4(10b)JA' ) flag++;
if ( version == '12.4(10b)JA1' ) flag++;
if ( version == '12.4(10b)JA2' ) flag++;
if ( version == '12.4(10b)JA3' ) flag++;
if ( version == '12.4(10b)JA4' ) flag++;
if ( version == '12.4(10b)JDA' ) flag++;
if ( version == '12.4(10b)JDA1' ) flag++;
if ( version == '12.4(10b)JDA2' ) flag++;
if ( version == '12.4(10b)JDA3' ) flag++;
if ( version == '12.4(10b)JDC' ) flag++;
if ( version == '12.4(10b)JDD' ) flag++;
if ( version == '12.4(10b)JDE' ) flag++;
if ( version == '12.4(10b)JX' ) flag++;
if ( version == '12.4(13d)JA' ) flag++;
if ( version == '12.4(13e)' ) flag++;
if ( version == '12.4(13f)' ) flag++;
if ( version == '12.4(15)MD' ) flag++;
if ( version == '12.4(15)MD1' ) flag++;
if ( version == '12.4(15)MD2' ) flag++;
if ( version == '12.4(15)MD3' ) flag++;
if ( version == '12.4(15)MD4' ) flag++;
if ( version == '12.4(15)MD5' ) flag++;
if ( version == '12.4(15)T10' ) flag++;
if ( version == '12.4(15)T11' ) flag++;
if ( version == '12.4(15)T12' ) flag++;
if ( version == '12.4(15)T13' ) flag++;
if ( version == '12.4(15)T13b' ) flag++;
if ( version == '12.4(15)T14' ) flag++;
if ( version == '12.4(15)T15' ) flag++;
if ( version == '12.4(15)T9' ) flag++;
if ( version == '12.4(15)XQ' ) flag++;
if ( version == '12.4(15)XQ1' ) flag++;
if ( version == '12.4(15)XQ2' ) flag++;
if ( version == '12.4(15)XQ2a' ) flag++;
if ( version == '12.4(15)XQ2b' ) flag++;
if ( version == '12.4(15)XQ2c' ) flag++;
if ( version == '12.4(15)XQ2d' ) flag++;
if ( version == '12.4(15)XQ3' ) flag++;
if ( version == '12.4(15)XQ4' ) flag++;
if ( version == '12.4(15)XQ5' ) flag++;
if ( version == '12.4(15)XQ6' ) flag++;
if ( version == '12.4(15)XQ7' ) flag++;
if ( version == '12.4(15)XQ8' ) flag++;
if ( version == '12.4(15)XR' ) flag++;
if ( version == '12.4(15)XR1' ) flag++;
if ( version == '12.4(15)XR10' ) flag++;
if ( version == '12.4(15)XR2' ) flag++;
if ( version == '12.4(15)XR3' ) flag++;
if ( version == '12.4(15)XR4' ) flag++;
if ( version == '12.4(15)XR5' ) flag++;
if ( version == '12.4(15)XR6' ) flag++;
if ( version == '12.4(15)XR7' ) flag++;
if ( version == '12.4(15)XR8' ) flag++;
if ( version == '12.4(15)XR9' ) flag++;
if ( version == '12.4(15)XZ' ) flag++;
if ( version == '12.4(15)XZ1' ) flag++;
if ( version == '12.4(15)XZ2' ) flag++;
if ( version == '12.4(16)MR2' ) flag++;
if ( version == '12.4(16b)' ) flag++;
if ( version == '12.4(16b)JA' ) flag++;
if ( version == '12.4(16b)JA1' ) flag++;
if ( version == '12.4(17a)' ) flag++;
if ( version == '12.4(17b)' ) flag++;
if ( version == '12.4(18)' ) flag++;
if ( version == '12.4(18a)' ) flag++;
if ( version == '12.4(18a)JA' ) flag++;
if ( version == '12.4(18a)JA1' ) flag++;
if ( version == '12.4(18a)JA2' ) flag++;
if ( version == '12.4(18a)JA3' ) flag++;
if ( version == '12.4(18b)' ) flag++;
if ( version == '12.4(18c)' ) flag++;
if ( version == '12.4(18d)' ) flag++;
if ( version == '12.4(18e)' ) flag++;
if ( version == '12.4(19)' ) flag++;
if ( version == '12.4(19)MR' ) flag++;
if ( version == '12.4(19)MR1' ) flag++;
if ( version == '12.4(19)MR2' ) flag++;
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
if ( version == '12.4(21)' ) flag++;
if ( version == '12.4(21a)' ) flag++;
if ( version == '12.4(21a)JA' ) flag++;
if ( version == '12.4(21a)JA1' ) flag++;
if ( version == '12.4(21a)JA2' ) flag++;
if ( version == '12.4(21a)JHA' ) flag++;
if ( version == '12.4(21a)JHB' ) flag++;
if ( version == '12.4(21a)JHB1' ) flag++;
if ( version == '12.4(21a)JHC' ) flag++;
if ( version == '12.4(21a)JX' ) flag++;
if ( version == '12.4(21a)JY' ) flag++;
if ( version == '12.4(21a)JZ' ) flag++;
if ( version == '12.4(21a)M1' ) flag++;
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
if ( version == '12.4(23)' ) flag++;
if ( version == '12.4(23a)' ) flag++;
if ( version == '12.4(23b)' ) flag++;
if ( version == '12.4(23b)M1' ) flag++;
if ( version == '12.4(23c)' ) flag++;
if ( version == '12.4(23c)JA' ) flag++;
if ( version == '12.4(23c)JA1' ) flag++;
if ( version == '12.4(23c)JA2' ) flag++;
if ( version == '12.4(23c)JA3' ) flag++;
if ( version == '12.4(23c)JY' ) flag++;
if ( version == '12.4(23c)JZ' ) flag++;
if ( version == '12.4(23d)' ) flag++;
if ( version == '12.4(23e)' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)GC3' ) flag++;
if ( version == '12.4(24)GC3a' ) flag++;
if ( version == '12.4(24)GC4' ) flag++;
if ( version == '12.4(24)MD' ) flag++;
if ( version == '12.4(24)MD1' ) flag++;
if ( version == '12.4(24)MD2' ) flag++;
if ( version == '12.4(24)MD3' ) flag++;
if ( version == '12.4(24)MD4' ) flag++;
if ( version == '12.4(24)MD5' ) flag++;
if ( version == '12.4(24)MD6' ) flag++;
if ( version == '12.4(24)MDA' ) flag++;
if ( version == '12.4(24)MDA1' ) flag++;
if ( version == '12.4(24)MDA10' ) flag++;
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
if ( version == '12.4(24)MDB3' ) flag++;
if ( version == '12.4(24)MDB4' ) flag++;
if ( version == '12.4(24)MDB5' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(24)T35c' ) flag++;
if ( version == '12.4(24)T3c' ) flag++;
if ( version == '12.4(24)T3e' ) flag++;
if ( version == '12.4(24)T3f' ) flag++;
if ( version == '12.4(24)T4' ) flag++;
if ( version == '12.4(24)T4a' ) flag++;
if ( version == '12.4(24)T4b' ) flag++;
if ( version == '12.4(24)T4c' ) flag++;
if ( version == '12.4(24)T5' ) flag++;
if ( version == '12.4(24)YE' ) flag++;
if ( version == '12.4(24)YE1' ) flag++;
if ( version == '12.4(24)YE2' ) flag++;
if ( version == '12.4(24)YE3' ) flag++;
if ( version == '12.4(24)YE3a' ) flag++;
if ( version == '12.4(24)YE3b' ) flag++;
if ( version == '12.4(24)YE3c' ) flag++;
if ( version == '12.4(24)YE4' ) flag++;
if ( version == '12.4(24)YE5' ) flag++;
if ( version == '12.4(24)YE6' ) flag++;
if ( version == '12.4(24)YE7' ) flag++;
if ( version == '12.4(24)YG1' ) flag++;
if ( version == '12.4(24)YG2' ) flag++;
if ( version == '12.4(24)YG3' ) flag++;
if ( version == '12.4(25)' ) flag++;
if ( version == '12.4(25a)' ) flag++;
if ( version == '12.4(25b)' ) flag++;
if ( version == '12.4(25c)' ) flag++;
if ( version == '12.4(25d)' ) flag++;
if ( version == '12.4(25d)JA' ) flag++;
if ( version == '12.4(25d)JA1' ) flag++;
if ( version == '12.4(25d)JAX' ) flag++;
if ( version == '12.4(25e)' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)M6a' ) flag++;
if ( version == '15.0(1)MR' ) flag++;
if ( version == '15.0(1)S' ) flag++;
if ( version == '15.0(1)S1' ) flag++;
if ( version == '15.0(1)S2' ) flag++;
if ( version == '15.0(1)S3a' ) flag++;
if ( version == '15.0(1)S4' ) flag++;
if ( version == '15.0(1)S4a' ) flag++;
if ( version == '15.0(1)SE' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;
if ( version == '15.0(1)XA5' ) flag++;
if ( version == '15.0(2)MR' ) flag++;
if ( version == '15.1(1)MR' ) flag++;
if ( version == '15.1(1)MR1' ) flag++;
if ( version == '15.1(1)MR2' ) flag++;
if ( version == '15.1(1)S' ) flag++;
if ( version == '15.1(1)S1' ) flag++;
if ( version == '15.1(1)S2' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)EY' ) flag++;
if ( version == '15.1(2)EY1' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)S' ) flag++;
if ( version == '15.1(2)S1' ) flag++;
if ( version == '15.1(2)S2' ) flag++;
if ( version == '15.1(2)SNG' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(3)S' ) flag++;
if ( version == '15.1(3)S0a' ) flag++;
if ( version == '15.1(3)S1' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ssh", "show ip ssh");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"version 1.99", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"version 2.0", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
