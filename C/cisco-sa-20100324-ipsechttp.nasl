#TRUSTED 99665a6ec90ccd208d897cb1a2bda544150895d92b1cef0a0fb12033300fcd791ef35a5117ce38143ca05dd6ccbae1b051303faee5c0f41b5e6e5421e59198e2e0e22d639660c54812f0e1630ad453c38b7de81d3f0dd3f574b4e017819205a148d589ea8890478fb418755c6059c3adb80952ec3240de582d9f81620fdd82fe04303706ba8e5a68a48f773dbed4000e34779d2aaa4477b6ab62c969120179f07695e0f1dfe00c0b965d59a0ade092bffdca88d564574508438633c134be8d6bf1a349a3171e1d8eb5e576e3888047ddf4e98f4492d70a05619ad49f7c0233da1a6b8ab0bdf7350063ab92be5fa78b20af5d1d7c9c5a98705fb6c04246cb5d18049a2ee39c7b81f82260c84203e5d90e1fd0230266404b581427ba99b725031e6c63744c8454808db1225e627879375260adb4873d3bf09ac5d0667954e26c1baa866954e8029fd3dfe1e51fc330a0068e429f92cd7450efe78d21bf88d33cb13964e30dbb2f5009fc5f23eb261e8ffe05895a7d8706ad85339618ffa60e6a659440914a41674bffeb5e749f833d1f5c6460bed3e3fb45420a6721213cc8eb19e497b8bf38d2cc573646720f0faaff42a615a2d8632ba9058b4671bb891defedc5b9592e613d3912a1cc70345f472b3d0787a00749fc50bf3ba7a02049ae6de0522acb87545c9e0bad4c0df2af8154ea9c10a769013abb0fedc139b00ccbc7b5
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20100324-ipsec.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(49051);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2010-0578");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtb13491");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100324-ipsec");

  script_name(english:"Cisco IOS Software IPsec Vulnerability (cisco-sa-20100324-ipsec)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A malformed Internet Key Exchange (IKE) packet may cause a device
running Cisco IOS Software to reload. Only Cisco 7200 Series and Cisco
7301 routers running Cisco IOS software with a VPN Acceleration Module
2+ (VAM2+) installed are affected. Cisco has released free software
updates that address this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100324-ipsec
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4b06cf5"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100324-ipsec."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");
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
if ( version == '12.2(33)SB' ) flag++;
if ( version == '12.2(33)SB1' ) flag++;
if ( version == '12.2(33)SB2' ) flag++;
if ( version == '12.2(33)SB3' ) flag++;
if ( version == '12.2(33)SB4' ) flag++;
if ( version == '12.2(33)SCA' ) flag++;
if ( version == '12.2(33)SCA1' ) flag++;
if ( version == '12.2(33)SCA2' ) flag++;
if ( version == '12.2(33)SCB' ) flag++;
if ( version == '12.2(33)SCB1' ) flag++;
if ( version == '12.2(33)SCB2' ) flag++;
if ( version == '12.2(33)SCB3' ) flag++;
if ( version == '12.2(33)SCB4' ) flag++;
if ( version == '12.2(33)SCB5' ) flag++;
if ( version == '12.2(33)SCC' ) flag++;
if ( version == '12.2(33)SRA5' ) flag++;
if ( version == '12.2(99)SX1003' ) flag++;
if ( version == '12.2(99)SX1006' ) flag++;
if ( version == '12.3(11)T' ) flag++;
if ( version == '12.3(11)T1' ) flag++;
if ( version == '12.3(11)T10' ) flag++;
if ( version == '12.3(11)T11' ) flag++;
if ( version == '12.3(11)T12' ) flag++;
if ( version == '12.3(11)T2' ) flag++;
if ( version == '12.3(11)T2a' ) flag++;
if ( version == '12.3(11)T3' ) flag++;
if ( version == '12.3(11)T4' ) flag++;
if ( version == '12.3(11)T5' ) flag++;
if ( version == '12.3(11)T6' ) flag++;
if ( version == '12.3(11)T7' ) flag++;
if ( version == '12.3(11)T8' ) flag++;
if ( version == '12.3(11)T9' ) flag++;
if ( version == '12.3(11)YF' ) flag++;
if ( version == '12.3(11)YF1' ) flag++;
if ( version == '12.3(11)YF2' ) flag++;
if ( version == '12.3(11)YF3' ) flag++;
if ( version == '12.3(11)YF4' ) flag++;
if ( version == '12.3(11)YK' ) flag++;
if ( version == '12.3(11)YR' ) flag++;
if ( version == '12.3(11)YR1' ) flag++;
if ( version == '12.3(11)YS2' ) flag++;
if ( version == '12.3(11)YZ2' ) flag++;
if ( version == '12.3(11)ZB' ) flag++;
if ( version == '12.3(11)ZB1' ) flag++;
if ( version == '12.3(11)ZB2' ) flag++;
if ( version == '12.3(14)T' ) flag++;
if ( version == '12.3(14)T1' ) flag++;
if ( version == '12.3(14)T2' ) flag++;
if ( version == '12.3(14)T3' ) flag++;
if ( version == '12.3(14)T4' ) flag++;
if ( version == '12.3(14)T5' ) flag++;
if ( version == '12.3(14)T6' ) flag++;
if ( version == '12.3(14)T7' ) flag++;
if ( version == '12.3(14)YQ' ) flag++;
if ( version == '12.3(14)YQ1' ) flag++;
if ( version == '12.3(14)YQ2' ) flag++;
if ( version == '12.3(14)YQ3' ) flag++;
if ( version == '12.3(14)YQ4' ) flag++;
if ( version == '12.3(14)YQ5' ) flag++;
if ( version == '12.3(14)YQ6' ) flag++;
if ( version == '12.3(14)YQ7' ) flag++;
if ( version == '12.3(14)YQ8' ) flag++;
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
if ( version == '12.3(14)YX2' ) flag++;
if ( version == '12.3(14)YX3' ) flag++;
if ( version == '12.3(14)YX4' ) flag++;
if ( version == '12.3(14)YX7' ) flag++;
if ( version == '12.3(14)YX8' ) flag++;
if ( version == '12.3(14)YX9' ) flag++;
if ( version == '12.3(2)XE5' ) flag++;
if ( version == '12.3(4)T' ) flag++;
if ( version == '12.3(4)T1' ) flag++;
if ( version == '12.3(4)T10' ) flag++;
if ( version == '12.3(4)T11' ) flag++;
if ( version == '12.3(4)T2' ) flag++;
if ( version == '12.3(4)T3' ) flag++;
if ( version == '12.3(4)T4' ) flag++;
if ( version == '12.3(4)T6' ) flag++;
if ( version == '12.3(4)T7' ) flag++;
if ( version == '12.3(4)T8' ) flag++;
if ( version == '12.3(4)T9' ) flag++;
if ( version == '12.3(4)TPC11b' ) flag++;
if ( version == '12.3(7)T' ) flag++;
if ( version == '12.3(7)T1' ) flag++;
if ( version == '12.3(7)T10' ) flag++;
if ( version == '12.3(7)T11' ) flag++;
if ( version == '12.3(7)T12' ) flag++;
if ( version == '12.3(7)T2' ) flag++;
if ( version == '12.3(7)T3' ) flag++;
if ( version == '12.3(7)T4' ) flag++;
if ( version == '12.3(7)T6' ) flag++;
if ( version == '12.3(7)T7' ) flag++;
if ( version == '12.3(7)T8' ) flag++;
if ( version == '12.3(7)T9' ) flag++;
if ( version == '12.3(7)XJ' ) flag++;
if ( version == '12.3(7)XJ1' ) flag++;
if ( version == '12.3(7)XJ2' ) flag++;
if ( version == '12.3(7)XR7' ) flag++;
if ( version == '12.3(8)T' ) flag++;
if ( version == '12.3(8)T1' ) flag++;
if ( version == '12.3(8)T10' ) flag++;
if ( version == '12.3(8)T11' ) flag++;
if ( version == '12.3(8)T3' ) flag++;
if ( version == '12.3(8)T4' ) flag++;
if ( version == '12.3(8)T5' ) flag++;
if ( version == '12.3(8)T6' ) flag++;
if ( version == '12.3(8)T7' ) flag++;
if ( version == '12.3(8)T8' ) flag++;
if ( version == '12.3(8)T9' ) flag++;
if ( version == '12.3(8)XU2' ) flag++;
if ( version == '12.3(8)XU3' ) flag++;
if ( version == '12.3(8)XU4' ) flag++;
if ( version == '12.3(8)XU5' ) flag++;
if ( version == '12.3(8)XW' ) flag++;
if ( version == '12.3(8)XW1' ) flag++;
if ( version == '12.3(8)XW1a' ) flag++;
if ( version == '12.3(8)XW1b' ) flag++;
if ( version == '12.3(8)XW2' ) flag++;
if ( version == '12.3(8)XW3' ) flag++;
if ( version == '12.3(8)XX2e' ) flag++;
if ( version == '12.3(8)YG6' ) flag++;
if ( version == '12.3(8)ZA' ) flag++;
if ( version == '12.3(8)ZA1' ) flag++;
if ( version == '12.4(1)' ) flag++;
if ( version == '12.4(10)' ) flag++;
if ( version == '12.4(10a)' ) flag++;
if ( version == '12.4(10b)' ) flag++;
if ( version == '12.4(10c)' ) flag++;
if ( version == '12.4(11)T' ) flag++;
if ( version == '12.4(11)T1' ) flag++;
if ( version == '12.4(11)T2' ) flag++;
if ( version == '12.4(11)T3' ) flag++;
if ( version == '12.4(11)T4' ) flag++;
if ( version == '12.4(11)XJ' ) flag++;
if ( version == '12.4(11)XJ2' ) flag++;
if ( version == '12.4(11)XJ3' ) flag++;
if ( version == '12.4(12)' ) flag++;
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
if ( version == '12.4(16)' ) flag++;
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
if ( version == '12.4(19a)' ) flag++;
if ( version == '12.4(19b)' ) flag++;
if ( version == '12.4(1a)' ) flag++;
if ( version == '12.4(1b)' ) flag++;
if ( version == '12.4(1c)' ) flag++;
if ( version == '12.4(2)T' ) flag++;
if ( version == '12.4(2)T1' ) flag++;
if ( version == '12.4(2)T2' ) flag++;
if ( version == '12.4(2)T3' ) flag++;
if ( version == '12.4(2)T4' ) flag++;
if ( version == '12.4(2)T5' ) flag++;
if ( version == '12.4(2)T6' ) flag++;
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
if ( version == '12.4(21)' ) flag++;
if ( version == '12.4(21a)' ) flag++;
if ( version == '12.4(21a)M1' ) flag++;
if ( version == '12.4(23)' ) flag++;
if ( version == '12.4(23a)' ) flag++;
if ( version == '12.4(23b)' ) flag++;
if ( version == '12.4(23b)M1' ) flag++;
if ( version == '12.4(23c)' ) flag++;
if ( version == '12.4(25)' ) flag++;
if ( version == '12.4(25a)' ) flag++;
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
if ( version == '12.4(4)T' ) flag++;
if ( version == '12.4(4)T1' ) flag++;
if ( version == '12.4(4)T2' ) flag++;
if ( version == '12.4(4)T3' ) flag++;
if ( version == '12.4(4)T4' ) flag++;
if ( version == '12.4(4)T5' ) flag++;
if ( version == '12.4(4)T6' ) flag++;
if ( version == '12.4(4)T7' ) flag++;
if ( version == '12.4(4)T8' ) flag++;
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
if ( version == '12.4(6)T6' ) flag++;
if ( version == '12.4(6)T7' ) flag++;
if ( version == '12.4(6)T8' ) flag++;
if ( version == '12.4(6)T9' ) flag++;
if ( version == '12.4(6)XE3' ) flag++;
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
if ( version == '12.4(9)T' ) flag++;
if ( version == '12.4(9)T1' ) flag++;
if ( version == '12.4(9)T2' ) flag++;
if ( version == '12.4(9)T3' ) flag++;
if ( version == '12.4(9)T4' ) flag++;
if ( version == '12.4(9)T5' ) flag++;
if ( version == '12.4(9)T6' ) flag++;
if ( version == '12.4(9)T7' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_crypto_engine_brief", "show crypto engine brief");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"State:\s+Enabled", multiline:TRUE, string:buf)) && (preg(pattern:"VAM2\+", multiline:TRUE, string:buf)) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
