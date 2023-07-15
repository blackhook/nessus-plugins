#TRUSTED 0cae755bb31669dd2f12584a5a99540fa70220838324fc89ec6c3216f4af6b3064d6b5b5a750b7c2764599b8d3d1e4a4ca10b7b69c1111e0b4856ef2dfd4a3bf73cc5cbd220985a41ebc0a028a7e3cad00d8d5757e086a50787ea7c2086a78b288fff01eb86a7eda9f47185bbc7712a001c714cbfb7d7b43ceae3e1075ddd700881b0250c62095d841eacab86cce28680c2bb464b5ac72811c8547ba68a69a269efdbdca32ec8a5c245ce5434824ee05c18fef3aab3bacac34e894ac5587ba63823f1c79f012ce4cae704a500b3fde2a9d4b07d35374dbe5f49df8791f08fee95bdfc788df02c785559b75c42978e846192d4603416098798bce5fb8c535e668b4a440e9699dcf1a124221e4425c40d8c6d11f888fca99f2d082b255817f9820e03e8351e08f0508f3d11e91a62e966dc8e5b4479ea65061245433c7fcb88efabfca40ce36d1d7099d997cb008e3ac96a49954c96f5dcc0d61c8b1f1b9683f87a400e5a3539f0b06901ba8d218e47641ca54fd4624f7faed8907a6e51706f67437fe8e48bc5a5bd741d07969faf1807bf9fb3d98ceaada244e08ae9a99d18b1c2616220a10a14b6027196b978dfe478857f366ff7d5ece59e5344b3321e60618ccb0af5f84de84a11de31efc6ca4c8106c0a1c34cfbb7eb5f8dfe2178770da08d5699cb6b73bac4e3e243757880ebe47748e37114b157c5b178ac124daa1c6da
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130327-pt.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(65889);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-1147");
  script_bugtraq_id(58740);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz35999");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130327-pt");

  script_name(english:"Cisco IOS Software Protocol Translation Vulnerability (cisco-sa-20130327-pt)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS Software Protocol Translation (PT) feature contains a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition. Cisco has released free
software updates that address this vulnerability. Workarounds that
mitigate this vulnerability are available."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130327-pt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73f412ba"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130327-pt."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
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
if ( version == '12.3(11)TO3' ) flag++;
if ( version == '12.3(11)XL' ) flag++;
if ( version == '12.3(11)XL1' ) flag++;
if ( version == '12.3(11)XL2' ) flag++;
if ( version == '12.3(11)XL3' ) flag++;
if ( version == '12.3(11)YF' ) flag++;
if ( version == '12.3(11)YK' ) flag++;
if ( version == '12.3(11)YK1' ) flag++;
if ( version == '12.3(11)YK2' ) flag++;
if ( version == '12.3(11)YK3' ) flag++;
if ( version == '12.3(11)YN' ) flag++;
if ( version == '12.3(11)YS' ) flag++;
if ( version == '12.3(11)YS1' ) flag++;
if ( version == '12.3(11)YS2' ) flag++;
if ( version == '12.3(11)YZ' ) flag++;
if ( version == '12.3(11)YZ1' ) flag++;
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
if ( version == '12.3(14)YM11' ) flag++;
if ( version == '12.3(14)YT' ) flag++;
if ( version == '12.3(14)YT1' ) flag++;
if ( version == '12.3(14)YU1' ) flag++;
if ( version == '12.3(14)YX4' ) flag++;
if ( version == '12.3(14)YX9' ) flag++;
if ( version == '12.3(7)XM' ) flag++;
if ( version == '12.3(7)XR1' ) flag++;
if ( version == '12.3(7)XR2' ) flag++;
if ( version == '12.3(7)XR3' ) flag++;
if ( version == '12.3(7)XR5' ) flag++;
if ( version == '12.3(7)XR6' ) flag++;
if ( version == '12.3(7)XR7' ) flag++;
if ( version == '12.3(8)T' ) flag++;
if ( version == '12.3(8)T1' ) flag++;
if ( version == '12.3(8)T10' ) flag++;
if ( version == '12.3(8)T11' ) flag++;
if ( version == '12.3(8)T2' ) flag++;
if ( version == '12.3(8)T3' ) flag++;
if ( version == '12.3(8)T4' ) flag++;
if ( version == '12.3(8)T5' ) flag++;
if ( version == '12.3(8)T6' ) flag++;
if ( version == '12.3(8)T7' ) flag++;
if ( version == '12.3(8)T8' ) flag++;
if ( version == '12.3(8)T9' ) flag++;
if ( version == '12.3(8)XW' ) flag++;
if ( version == '12.3(8)XW1' ) flag++;
if ( version == '12.3(8)XW1a' ) flag++;
if ( version == '12.3(8)XW2' ) flag++;
if ( version == '12.3(8)XW3' ) flag++;
if ( version == '12.3(8)XX2d' ) flag++;
if ( version == '12.3(8)XX2e' ) flag++;
if ( version == '12.3(8)YA' ) flag++;
if ( version == '12.3(8)YA1' ) flag++;
if ( version == '12.3(8)YC' ) flag++;
if ( version == '12.3(8)YC1' ) flag++;
if ( version == '12.3(8)YC2' ) flag++;
if ( version == '12.3(8)YC3' ) flag++;
if ( version == '12.3(8)YG' ) flag++;
if ( version == '12.3(8)YG1' ) flag++;
if ( version == '12.3(8)YG2' ) flag++;
if ( version == '12.3(8)YG3' ) flag++;
if ( version == '12.3(8)YG4' ) flag++;
if ( version == '12.3(8)YG5' ) flag++;
if ( version == '12.3(8)YG6' ) flag++;
if ( version == '12.3(8)YG7' ) flag++;
if ( version == '12.3(8)YH' ) flag++;
if ( version == '12.3(8)YI' ) flag++;
if ( version == '12.3(8)YI1' ) flag++;
if ( version == '12.3(8)YI2' ) flag++;
if ( version == '12.3(8)YI3' ) flag++;
if ( version == '12.3(8)ZA' ) flag++;
if ( version == '12.3(8)ZA1' ) flag++;
if ( version == '12.4(1)' ) flag++;
if ( version == '12.4(10)' ) flag++;
if ( version == '12.4(10a)' ) flag++;
if ( version == '12.4(10b)' ) flag++;
if ( version == '12.4(10c)' ) flag++;
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
if ( version == '12.4(15)SW' ) flag++;
if ( version == '12.4(15)SW1' ) flag++;
if ( version == '12.4(15)SW2' ) flag++;
if ( version == '12.4(15)SW3' ) flag++;
if ( version == '12.4(15)SW4' ) flag++;
if ( version == '12.4(15)SW5' ) flag++;
if ( version == '12.4(15)SW6' ) flag++;
if ( version == '12.4(15)SW7' ) flag++;
if ( version == '12.4(15)SW8' ) flag++;
if ( version == '12.4(15)SW8a' ) flag++;
if ( version == '12.4(15)SW9' ) flag++;
if ( version == '12.4(15)T' ) flag++;
if ( version == '12.4(15)T1' ) flag++;
if ( version == '12.4(15)T10' ) flag++;
if ( version == '12.4(15)T11' ) flag++;
if ( version == '12.4(15)T12' ) flag++;
if ( version == '12.4(15)T13' ) flag++;
if ( version == '12.4(15)T13b' ) flag++;
if ( version == '12.4(15)T14' ) flag++;
if ( version == '12.4(15)T15' ) flag++;
if ( version == '12.4(15)T16' ) flag++;
if ( version == '12.4(15)T17' ) flag++;
if ( version == '12.4(15)T2' ) flag++;
if ( version == '12.4(15)T3' ) flag++;
if ( version == '12.4(15)T4' ) flag++;
if ( version == '12.4(15)T5' ) flag++;
if ( version == '12.4(15)T6' ) flag++;
if ( version == '12.4(15)T6a' ) flag++;
if ( version == '12.4(15)T7' ) flag++;
if ( version == '12.4(15)T8' ) flag++;
if ( version == '12.4(15)T9' ) flag++;
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
if ( version == '12.4(2)XB6' ) flag++;
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
if ( version == '12.4(21a)M1' ) flag++;
if ( version == '12.4(22)GC1' ) flag++;
if ( version == '12.4(22)GC1a' ) flag++;
if ( version == '12.4(22)T' ) flag++;
if ( version == '12.4(22)T1' ) flag++;
if ( version == '12.4(22)T2' ) flag++;
if ( version == '12.4(22)T3' ) flag++;
if ( version == '12.4(22)T4' ) flag++;
if ( version == '12.4(22)T5' ) flag++;
if ( version == '12.4(22)YB' ) flag++;
if ( version == '12.4(22)YB1' ) flag++;
if ( version == '12.4(22)YB4' ) flag++;
if ( version == '12.4(22)YB5' ) flag++;
if ( version == '12.4(22)YB6' ) flag++;
if ( version == '12.4(22)YB7' ) flag++;
if ( version == '12.4(22)YB8' ) flag++;
if ( version == '12.4(23)' ) flag++;
if ( version == '12.4(23a)' ) flag++;
if ( version == '12.4(23b)' ) flag++;
if ( version == '12.4(23b)M1' ) flag++;
if ( version == '12.4(23c)' ) flag++;
if ( version == '12.4(23d)' ) flag++;
if ( version == '12.4(23e)' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)GC3' ) flag++;
if ( version == '12.4(24)GC3a' ) flag++;
if ( version == '12.4(24)GC4' ) flag++;
if ( version == '12.4(24)GC5' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(24)T4' ) flag++;
if ( version == '12.4(24)T5' ) flag++;
if ( version == '12.4(24)T6' ) flag++;
if ( version == '12.4(24)T7' ) flag++;
if ( version == '12.4(24)T8' ) flag++;
if ( version == '12.4(25)' ) flag++;
if ( version == '12.4(25a)' ) flag++;
if ( version == '12.4(25b)' ) flag++;
if ( version == '12.4(25c)' ) flag++;
if ( version == '12.4(25d)' ) flag++;
if ( version == '12.4(25e)' ) flag++;
if ( version == '12.4(25f)' ) flag++;
if ( version == '12.4(25g)' ) flag++;
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
if ( version == '12.4(9)T0a' ) flag++;
if ( version == '12.4(9)T1' ) flag++;
if ( version == '12.4(9)T2' ) flag++;
if ( version == '12.4(9)T3' ) flag++;
if ( version == '12.4(9)T4' ) flag++;
if ( version == '12.4(9)T5' ) flag++;
if ( version == '12.4(9)T6' ) flag++;
if ( version == '12.4(9)T7' ) flag++;
if ( version == '12.4(9)XG2' ) flag++;
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
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(1)T2' ) flag++;
if ( version == '15.2(1)T3' ) flag++;
if ( version == '15.2(1)T3a' ) flag++;
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(2)JA' ) flag++;
if ( version == '15.2(2)T' ) flag++;
if ( version == '15.2(2)T1' ) flag++;
if ( version == '15.2(2)T2' ) flag++;
if ( version == '15.2(2a)JA' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)T2' ) flag++;
if ( version == '15.2(4)M' ) flag++;
if ( version == '15.2(4)M1' ) flag++;
if ( version == '15.2(4)M2' ) flag++;
if ( version == '15.2(4)XB10' ) flag++;
if ( version == '15.3(1)T' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"use telnet", multiline:TRUE, string:buf)) && (preg(pattern:"telnet to pad", multiline:TRUE, string:buf)) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    buf = cisco_command_kb_item("Host/Cisco/Config/show_translate", "show translate");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"From:.+[Pp]ort 23", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
