#TRUSTED 3eaecef58c8493a84d9ecc9b00d9b8e103b428b94c6f99117e36fe46fd7ad009a44168e48f0408b7ac65e2e223de7980c79850e268b06dbbd4cf79a658597bc3611f6ce6a5640987f37aca5c32c866a55a7bf2cee5ee2a2cc73ae99a293c237abe9fdf479e286b640560873125d1e8d73cca81d68716993e97aea681cbd88fcc36270876e8adc767677faf3afb12173eaf990e741e7ac523d51c301a1cc8cc2888c479fcb21e61554bb33ad41cb6281d752fb8fa22525ea791ae2703378d5d87bc0977ee3b3f7d6c401ffa4c6558112771b5ca9b35c3f48ee337a3cab32f1486bbf4b616489d9acf1ae3832260f37f547743149ad42823bd4aecc6ecf7d8b95f37b4a19f19cd2c29c6c2af7b31bedf8df72cea9a9f297b1ea602304b07d2ce361180fb3398f38cb2cb072dcbe18c73b3c5dff3f58a6cb39f8a4f8c8a04d1ec88c558185ad275fb209fffe155542b3302d0efe782868683d1b7c11ab333ef3c5e52c6b0674da57ee7bd78488521c80c0145e8fea7c90b01c2b5b5a948d2d6e3937658f05a66c33b2b3dfe8fe9c0a2cfc644b6f5eb819c1ffd0f7944d67698423ef14a38491a5c97477b5a6c3471f17d97380767abee36f0ff21ed47d230a83aa7cd2818b7cbe610aa97d1b89587f7b7773ec5c4593f54d676df9d2a8be7e5c31a84bc37913ea95794f94063ac4707ca6173e037bddd09e36aa4c549dec3771025
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20100922-igmp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(17783);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2010-2830");
  script_bugtraq_id(43396);
  script_xref(name:"CISCO-BUG-ID", value:"CSCte14603");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100922-igmp");

  script_name(english:"Cisco IOS Software Internet Group Management Protocol Denial of Service Vulnerability (cisco-sa-20100922-igmp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the Internet Group Management Protocol (IGMP)
version 3 implementation of Cisco IOS Software and Cisco IOS XE
Software allows a remote unauthenticated attacker to cause a reload of
an affected device. Repeated attempts to exploit this vulnerability
could result in a sustained denial of service (DoS) condition. Cisco
has released free software updates that address this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100922-igmp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa751f63"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100922-igmp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

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
if ( version == '12.2(33)SRE' ) flag++;
if ( version == '12.2(33)SRE0a' ) flag++;
if ( version == '12.2(33)XNE' ) flag++;
if ( version == '12.2(33)XNE1' ) flag++;
if ( version == '12.2(33)ZI' ) flag++;
if ( version == '12.3(11)YK' ) flag++;
if ( version == '12.3(11)YK1' ) flag++;
if ( version == '12.3(11)YK2' ) flag++;
if ( version == '12.3(11)YK3' ) flag++;
if ( version == '12.3(11)YL' ) flag++;
if ( version == '12.3(11)YL1' ) flag++;
if ( version == '12.3(11)YL2' ) flag++;
if ( version == '12.3(11)YN' ) flag++;
if ( version == '12.3(11)YS' ) flag++;
if ( version == '12.3(11)YS1' ) flag++;
if ( version == '12.3(11)YS2' ) flag++;
if ( version == '12.3(14)T' ) flag++;
if ( version == '12.3(14)T1' ) flag++;
if ( version == '12.3(14)T2' ) flag++;
if ( version == '12.3(14)T3' ) flag++;
if ( version == '12.3(14)T4' ) flag++;
if ( version == '12.3(14)T5' ) flag++;
if ( version == '12.3(14)T6' ) flag++;
if ( version == '12.3(14)T7' ) flag++;
if ( version == '12.3(14)YM1' ) flag++;
if ( version == '12.3(14)YM10' ) flag++;
if ( version == '12.3(14)YM11' ) flag++;
if ( version == '12.3(14)YM12' ) flag++;
if ( version == '12.3(14)YM13' ) flag++;
if ( version == '12.3(14)YM2' ) flag++;
if ( version == '12.3(14)YM3' ) flag++;
if ( version == '12.3(14)YM4' ) flag++;
if ( version == '12.3(14)YM5' ) flag++;
if ( version == '12.3(14)YM6' ) flag++;
if ( version == '12.3(14)YM7' ) flag++;
if ( version == '12.3(14)YM8' ) flag++;
if ( version == '12.3(14)YM9' ) flag++;
if ( version == '12.3(14)YQ' ) flag++;
if ( version == '12.3(14)YQ1' ) flag++;
if ( version == '12.3(14)YQ2' ) flag++;
if ( version == '12.3(14)YQ3' ) flag++;
if ( version == '12.3(14)YQ4' ) flag++;
if ( version == '12.3(14)YQ5' ) flag++;
if ( version == '12.3(14)YQ6' ) flag++;
if ( version == '12.3(14)YQ7' ) flag++;
if ( version == '12.3(14)YQ8' ) flag++;
if ( version == '12.3(14)YT' ) flag++;
if ( version == '12.3(14)YT1' ) flag++;
if ( version == '12.3(14)YU' ) flag++;
if ( version == '12.3(14)YU1' ) flag++;
if ( version == '12.3(14)YX' ) flag++;
if ( version == '12.3(14)YX1' ) flag++;
if ( version == '12.3(14)YX10' ) flag++;
if ( version == '12.3(14)YX11' ) flag++;
if ( version == '12.3(14)YX12' ) flag++;
if ( version == '12.3(14)YX13' ) flag++;
if ( version == '12.3(14)YX14' ) flag++;
if ( version == '12.3(14)YX15' ) flag++;
if ( version == '12.3(14)YX16' ) flag++;
if ( version == '12.3(14)YX2' ) flag++;
if ( version == '12.3(14)YX3' ) flag++;
if ( version == '12.3(14)YX4' ) flag++;
if ( version == '12.3(14)YX7' ) flag++;
if ( version == '12.3(14)YX8' ) flag++;
if ( version == '12.3(14)YX9' ) flag++;
if ( version == '12.4(1)' ) flag++;
if ( version == '12.4(10)' ) flag++;
if ( version == '12.4(10a)' ) flag++;
if ( version == '12.4(10b)' ) flag++;
if ( version == '12.4(10c)' ) flag++;
if ( version == '12.4(11)MD' ) flag++;
if ( version == '12.4(11)MD1' ) flag++;
if ( version == '12.4(11)MD10' ) flag++;
if ( version == '12.4(11)MD2' ) flag++;
if ( version == '12.4(11)MD3' ) flag++;
if ( version == '12.4(11)MD4' ) flag++;
if ( version == '12.4(11)MD5' ) flag++;
if ( version == '12.4(11)MD6' ) flag++;
if ( version == '12.4(11)MD7' ) flag++;
if ( version == '12.4(11)MD8' ) flag++;
if ( version == '12.4(11)MD9' ) flag++;
if ( version == '12.4(11)MR' ) flag++;
if ( version == '12.4(11)SW' ) flag++;
if ( version == '12.4(11)SW1' ) flag++;
if ( version == '12.4(11)SW2' ) flag++;
if ( version == '12.4(11)SW3' ) flag++;
if ( version == '12.4(11)T' ) flag++;
if ( version == '12.4(11)T1' ) flag++;
if ( version == '12.4(11)T2' ) flag++;
if ( version == '12.4(11)T3' ) flag++;
if ( version == '12.4(11)T4' ) flag++;
if ( version == '12.4(11)XJ' ) flag++;
if ( version == '12.4(11)XJ1' ) flag++;
if ( version == '12.4(11)XJ2' ) flag++;
if ( version == '12.4(11)XJ3' ) flag++;
if ( version == '12.4(11)XJ4' ) flag++;
if ( version == '12.4(11)XJ5' ) flag++;
if ( version == '12.4(11)XJ6' ) flag++;
if ( version == '12.4(11)XV' ) flag++;
if ( version == '12.4(11)XV1' ) flag++;
if ( version == '12.4(11)XW' ) flag++;
if ( version == '12.4(11)XW1' ) flag++;
if ( version == '12.4(11)XW10' ) flag++;
if ( version == '12.4(11)XW2' ) flag++;
if ( version == '12.4(11)XW3' ) flag++;
if ( version == '12.4(11)XW4' ) flag++;
if ( version == '12.4(11)XW5' ) flag++;
if ( version == '12.4(11)XW6' ) flag++;
if ( version == '12.4(11)XW7' ) flag++;
if ( version == '12.4(11)XW8' ) flag++;
if ( version == '12.4(11)XW9' ) flag++;
if ( version == '12.4(12)' ) flag++;
if ( version == '12.4(12)MR' ) flag++;
if ( version == '12.4(12)MR1' ) flag++;
if ( version == '12.4(12)MR2' ) flag++;
if ( version == '12.4(12a)' ) flag++;
if ( version == '12.4(12b)' ) flag++;
if ( version == '12.4(12c)' ) flag++;
if ( version == '12.4(13)' ) flag++;
if ( version == '12.4(13a)' ) flag++;
if ( version == '12.4(13b)' ) flag++;
if ( version == '12.4(13c)' ) flag++;
if ( version == '12.4(13d)' ) flag++;
if ( version == '12.4(13e)' ) flag++;
if ( version == '12.4(13f)' ) flag++;
if ( version == '12.4(14)XK' ) flag++;
if ( version == '12.4(15)MD' ) flag++;
if ( version == '12.4(15)MD1' ) flag++;
if ( version == '12.4(15)MD2' ) flag++;
if ( version == '12.4(15)MD3' ) flag++;
if ( version == '12.4(15)MD4' ) flag++;
if ( version == '12.4(15)SW' ) flag++;
if ( version == '12.4(15)SW1' ) flag++;
if ( version == '12.4(15)SW2' ) flag++;
if ( version == '12.4(15)SW3' ) flag++;
if ( version == '12.4(15)SW4' ) flag++;
if ( version == '12.4(15)SW5' ) flag++;
if ( version == '12.4(15)T' ) flag++;
if ( version == '12.4(15)T1' ) flag++;
if ( version == '12.4(15)T10' ) flag++;
if ( version == '12.4(15)T11' ) flag++;
if ( version == '12.4(15)T12' ) flag++;
if ( version == '12.4(15)T13' ) flag++;
if ( version == '12.4(15)T2' ) flag++;
if ( version == '12.4(15)T3' ) flag++;
if ( version == '12.4(15)T4' ) flag++;
if ( version == '12.4(15)T5' ) flag++;
if ( version == '12.4(15)T6' ) flag++;
if ( version == '12.4(15)T6a' ) flag++;
if ( version == '12.4(15)T7' ) flag++;
if ( version == '12.4(15)T8' ) flag++;
if ( version == '12.4(15)T9' ) flag++;
if ( version == '12.4(15)XF' ) flag++;
if ( version == '12.4(15)XL' ) flag++;
if ( version == '12.4(15)XL1' ) flag++;
if ( version == '12.4(15)XL2' ) flag++;
if ( version == '12.4(15)XL3' ) flag++;
if ( version == '12.4(15)XL4' ) flag++;
if ( version == '12.4(15)XL5' ) flag++;
if ( version == '12.4(15)XM' ) flag++;
if ( version == '12.4(15)XM1' ) flag++;
if ( version == '12.4(15)XM2' ) flag++;
if ( version == '12.4(15)XM3' ) flag++;
if ( version == '12.4(15)XN' ) flag++;
if ( version == '12.4(15)XQ' ) flag++;
if ( version == '12.4(15)XQ1' ) flag++;
if ( version == '12.4(15)XQ2' ) flag++;
if ( version == '12.4(15)XQ2a' ) flag++;
if ( version == '12.4(15)XQ2b' ) flag++;
if ( version == '12.4(15)XQ2c' ) flag++;
if ( version == '12.4(15)XQ3' ) flag++;
if ( version == '12.4(15)XQ4' ) flag++;
if ( version == '12.4(15)XQ5' ) flag++;
if ( version == '12.4(15)XR' ) flag++;
if ( version == '12.4(15)XR1' ) flag++;
if ( version == '12.4(15)XR2' ) flag++;
if ( version == '12.4(15)XR3' ) flag++;
if ( version == '12.4(15)XR4' ) flag++;
if ( version == '12.4(15)XR5' ) flag++;
if ( version == '12.4(15)XR6' ) flag++;
if ( version == '12.4(15)XR7' ) flag++;
if ( version == '12.4(15)XR8' ) flag++;
if ( version == '12.4(15)XY' ) flag++;
if ( version == '12.4(15)XY1' ) flag++;
if ( version == '12.4(15)XY2' ) flag++;
if ( version == '12.4(15)XY3' ) flag++;
if ( version == '12.4(15)XY4' ) flag++;
if ( version == '12.4(15)XY5' ) flag++;
if ( version == '12.4(15)XZ' ) flag++;
if ( version == '12.4(15)XZ1' ) flag++;
if ( version == '12.4(15)XZ2' ) flag++;
if ( version == '12.4(16)' ) flag++;
if ( version == '12.4(16)MR' ) flag++;
if ( version == '12.4(16)MR1' ) flag++;
if ( version == '12.4(16)MR2' ) flag++;
if ( version == '12.4(16a)' ) flag++;
if ( version == '12.4(16b)' ) flag++;
if ( version == '12.4(17)' ) flag++;
if ( version == '12.4(17a)' ) flag++;
if ( version == '12.4(17b)' ) flag++;
if ( version == '12.4(18)' ) flag++;
if ( version == '12.4(18a)' ) flag++;
if ( version == '12.4(18b)' ) flag++;
if ( version == '12.4(18c)' ) flag++;
if ( version == '12.4(18d)' ) flag++;
if ( version == '12.4(18e)' ) flag++;
if ( version == '12.4(19)' ) flag++;
if ( version == '12.4(19)MR' ) flag++;
if ( version == '12.4(19)MR1' ) flag++;
if ( version == '12.4(19)MR2' ) flag++;
if ( version == '12.4(1a)' ) flag++;
if ( version == '12.4(1b)' ) flag++;
if ( version == '12.4(1c)' ) flag++;
if ( version == '12.4(2)MR' ) flag++;
if ( version == '12.4(2)MR1' ) flag++;
if ( version == '12.4(2)T' ) flag++;
if ( version == '12.4(2)T1' ) flag++;
if ( version == '12.4(2)T2' ) flag++;
if ( version == '12.4(2)T3' ) flag++;
if ( version == '12.4(2)T4' ) flag++;
if ( version == '12.4(2)T5' ) flag++;
if ( version == '12.4(2)T6' ) flag++;
if ( version == '12.4(2)XA' ) flag++;
if ( version == '12.4(2)XA1' ) flag++;
if ( version == '12.4(2)XA2' ) flag++;
if ( version == '12.4(2)XB' ) flag++;
if ( version == '12.4(2)XB1' ) flag++;
if ( version == '12.4(2)XB10' ) flag++;
if ( version == '12.4(2)XB11' ) flag++;
if ( version == '12.4(2)XB2' ) flag++;
if ( version == '12.4(2)XB3' ) flag++;
if ( version == '12.4(2)XB4' ) flag++;
if ( version == '12.4(2)XB5' ) flag++;
if ( version == '12.4(2)XB6' ) flag++;
if ( version == '12.4(2)XB7' ) flag++;
if ( version == '12.4(2)XB8' ) flag++;
if ( version == '12.4(2)XB9' ) flag++;
if ( version == '12.4(20)MR' ) flag++;
if ( version == '12.4(20)MR2' ) flag++;
if ( version == '12.4(20)MRA' ) flag++;
if ( version == '12.4(20)T' ) flag++;
if ( version == '12.4(20)T1' ) flag++;
if ( version == '12.4(20)T2' ) flag++;
if ( version == '12.4(20)T3' ) flag++;
if ( version == '12.4(20)T4' ) flag++;
if ( version == '12.4(20)YA' ) flag++;
if ( version == '12.4(20)YA1' ) flag++;
if ( version == '12.4(20)YA2' ) flag++;
if ( version == '12.4(20)YA3' ) flag++;
if ( version == '12.4(21)' ) flag++;
if ( version == '12.4(21a)' ) flag++;
if ( version == '12.4(21a)M1' ) flag++;
if ( version == '12.4(22)GC1' ) flag++;
if ( version == '12.4(22)MD' ) flag++;
if ( version == '12.4(22)MD1' ) flag++;
if ( version == '12.4(22)MDA' ) flag++;
if ( version == '12.4(22)MDA1' ) flag++;
if ( version == '12.4(22)MDA2' ) flag++;
if ( version == '12.4(22)MDA3' ) flag++;
if ( version == '12.4(22)MF' ) flag++;
if ( version == '12.4(22)T' ) flag++;
if ( version == '12.4(22)T1' ) flag++;
if ( version == '12.4(22)T2' ) flag++;
if ( version == '12.4(22)T3' ) flag++;
if ( version == '12.4(22)XR' ) flag++;
if ( version == '12.4(22)XR1' ) flag++;
if ( version == '12.4(22)XR2' ) flag++;
if ( version == '12.4(22)XR3' ) flag++;
if ( version == '12.4(22)XR4' ) flag++;
if ( version == '12.4(22)XR5' ) flag++;
if ( version == '12.4(22)XR6' ) flag++;
if ( version == '12.4(22)YB' ) flag++;
if ( version == '12.4(22)YB1' ) flag++;
if ( version == '12.4(22)YB4' ) flag++;
if ( version == '12.4(22)YB5' ) flag++;
if ( version == '12.4(22)YD' ) flag++;
if ( version == '12.4(22)YD1' ) flag++;
if ( version == '12.4(22)YD2' ) flag++;
if ( version == '12.4(22)YD3' ) flag++;
if ( version == '12.4(22)YE' ) flag++;
if ( version == '12.4(22)YE1' ) flag++;
if ( version == '12.4(22)YE2' ) flag++;
if ( version == '12.4(22)YE3' ) flag++;
if ( version == '12.4(23)' ) flag++;
if ( version == '12.4(23a)' ) flag++;
if ( version == '12.4(23b)' ) flag++;
if ( version == '12.4(23b)M1' ) flag++;
if ( version == '12.4(23c)' ) flag++;
if ( version == '12.4(23d)' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)MD' ) flag++;
if ( version == '12.4(24)MD1' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)YE' ) flag++;
if ( version == '12.4(24)YG1' ) flag++;
if ( version == '12.4(24)YG2' ) flag++;
if ( version == '12.4(25)' ) flag++;
if ( version == '12.4(25a)' ) flag++;
if ( version == '12.4(25b)' ) flag++;
if ( version == '12.4(25c)' ) flag++;
if ( version == '12.4(3)' ) flag++;
if ( version == '12.4(3a)' ) flag++;
if ( version == '12.4(3b)' ) flag++;
if ( version == '12.4(3c)' ) flag++;
if ( version == '12.4(3d)' ) flag++;
if ( version == '12.4(3e)' ) flag++;
if ( version == '12.4(3f)' ) flag++;
if ( version == '12.4(3g)' ) flag++;
if ( version == '12.4(3h)' ) flag++;
if ( version == '12.4(3i)' ) flag++;
if ( version == '12.4(3j)' ) flag++;
if ( version == '12.4(4)MR' ) flag++;
if ( version == '12.4(4)MR1' ) flag++;
if ( version == '12.4(4)T' ) flag++;
if ( version == '12.4(4)T1' ) flag++;
if ( version == '12.4(4)T2' ) flag++;
if ( version == '12.4(4)T3' ) flag++;
if ( version == '12.4(4)T4' ) flag++;
if ( version == '12.4(4)T5' ) flag++;
if ( version == '12.4(4)T6' ) flag++;
if ( version == '12.4(4)T7' ) flag++;
if ( version == '12.4(4)T8' ) flag++;
if ( version == '12.4(4)XC' ) flag++;
if ( version == '12.4(4)XC1' ) flag++;
if ( version == '12.4(4)XC2' ) flag++;
if ( version == '12.4(4)XC3' ) flag++;
if ( version == '12.4(4)XC4' ) flag++;
if ( version == '12.4(4)XC5' ) flag++;
if ( version == '12.4(4)XC6' ) flag++;
if ( version == '12.4(4)XC7' ) flag++;
if ( version == '12.4(4)XD' ) flag++;
if ( version == '12.4(4)XD1' ) flag++;
if ( version == '12.4(4)XD10' ) flag++;
if ( version == '12.4(4)XD11' ) flag++;
if ( version == '12.4(4)XD12' ) flag++;
if ( version == '12.4(4)XD2' ) flag++;
if ( version == '12.4(4)XD3' ) flag++;
if ( version == '12.4(4)XD4' ) flag++;
if ( version == '12.4(4)XD5' ) flag++;
if ( version == '12.4(4)XD6' ) flag++;
if ( version == '12.4(4)XD7' ) flag++;
if ( version == '12.4(4)XD8' ) flag++;
if ( version == '12.4(4)XD9' ) flag++;
if ( version == '12.4(5)' ) flag++;
if ( version == '12.4(5a)' ) flag++;
if ( version == '12.4(5a)M0' ) flag++;
if ( version == '12.4(5b)' ) flag++;
if ( version == '12.4(5c)' ) flag++;
if ( version == '12.4(6)MR' ) flag++;
if ( version == '12.4(6)MR1' ) flag++;
if ( version == '12.4(6)T' ) flag++;
if ( version == '12.4(6)T1' ) flag++;
if ( version == '12.4(6)T10' ) flag++;
if ( version == '12.4(6)T11' ) flag++;
if ( version == '12.4(6)T12' ) flag++;
if ( version == '12.4(6)T2' ) flag++;
if ( version == '12.4(6)T3' ) flag++;
if ( version == '12.4(6)T4' ) flag++;
if ( version == '12.4(6)T5' ) flag++;
if ( version == '12.4(6)T5a' ) flag++;
if ( version == '12.4(6)T5b' ) flag++;
if ( version == '12.4(6)T5c' ) flag++;
if ( version == '12.4(6)T5d' ) flag++;
if ( version == '12.4(6)T5e' ) flag++;
if ( version == '12.4(6)T5f' ) flag++;
if ( version == '12.4(6)T6' ) flag++;
if ( version == '12.4(6)T7' ) flag++;
if ( version == '12.4(6)T8' ) flag++;
if ( version == '12.4(6)T9' ) flag++;
if ( version == '12.4(6)XE' ) flag++;
if ( version == '12.4(6)XE1' ) flag++;
if ( version == '12.4(6)XE2' ) flag++;
if ( version == '12.4(6)XE3' ) flag++;
if ( version == '12.4(6)XE4' ) flag++;
if ( version == '12.4(6)XP' ) flag++;
if ( version == '12.4(6)XT' ) flag++;
if ( version == '12.4(6)XT1' ) flag++;
if ( version == '12.4(6)XT2' ) flag++;
if ( version == '12.4(7)' ) flag++;
if ( version == '12.4(7a)' ) flag++;
if ( version == '12.4(7b)' ) flag++;
if ( version == '12.4(7c)' ) flag++;
if ( version == '12.4(7d)' ) flag++;
if ( version == '12.4(7e)' ) flag++;
if ( version == '12.4(7f)' ) flag++;
if ( version == '12.4(7g)' ) flag++;
if ( version == '12.4(7h)' ) flag++;
if ( version == '12.4(8)' ) flag++;
if ( version == '12.4(8a)' ) flag++;
if ( version == '12.4(8b)' ) flag++;
if ( version == '12.4(8c)' ) flag++;
if ( version == '12.4(8d)' ) flag++;
if ( version == '12.4(9)MR' ) flag++;
if ( version == '12.4(9)T' ) flag++;
if ( version == '12.4(9)T0a' ) flag++;
if ( version == '12.4(9)T1' ) flag++;
if ( version == '12.4(9)T2' ) flag++;
if ( version == '12.4(9)T3' ) flag++;
if ( version == '12.4(9)T4' ) flag++;
if ( version == '12.4(9)T5' ) flag++;
if ( version == '12.4(9)T6' ) flag++;
if ( version == '12.4(9)T7' ) flag++;
if ( version == '12.4(9)XG' ) flag++;
if ( version == '12.4(9)XG1' ) flag++;
if ( version == '12.4(9)XG2' ) flag++;
if ( version == '12.4(9)XG3' ) flag++;
if ( version == '12.4(9)XG4' ) flag++;
if ( version == '12.4(9)XG5' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip\s+igmp\s+version\s+3", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ip\s+pim.*", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
