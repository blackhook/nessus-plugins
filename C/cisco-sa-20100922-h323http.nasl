#TRUSTED 368bc457a314df90500407b53e6ff4d7e173e06dfe77ea9d50bd189970942c8f1996f022732efa973a3b45f2dafa6a0e52c76fcae8365943bb2f7369f677774b360878bf15333360f955d7124cb96046d3f21dee02e59a08a655d948dba94d577455e9c254964bbe43c8e93c22e4f191bf78216d938c61029aabd0fac54accc22d2fefc155b170a1b805c15ff0da6cb6648cf354951cae90d44bb066972ea7a57bad9a130773bfa024c1d497e8970f00dd1d9f1f33251f63cbec312a01d49ff8268c17138e82f7fe9a5ff967d10daf889b6ef2b236bc89f675a739a9bc4e49749bcb0a2c53d77fb3ef273dde7a232048aad860bd55c655d346a7c36ea5b6903ef602a72c3d46bac495e577fff1ab4a87cb7f68adadc1bba02ec388860887ba858301f4b069c34165ebe21afd73724bce32f6da0864ed44014916788e9b03da88622d3157ec50559ce63135ddccdbbc20bbe7d4400b4cf448243796b8839d0974d1b51ec4c831ad8a80e53812926559988a2d6dfeb7ef9d6eb8335830c03e1a1590314537a1af0aba03070b0b9c91fc567b5dbd67db308494c73928ff9526d6d535f5c48b8c24ba3b85c45060bc9c7a21aa42cd94f80970e16ccb550782a0b8eb97d618e312addcf6967e207d32adf662982af67a22a4168bdec68e03c3a38c830b41b35cac241feac5f8328d7673fa349001f5c6e5479632ec51486df72855c2
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20100922-h323.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(49647);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2010-2828", "CVE-2010-2829");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtc73759");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100922-h323");

  script_name(english:"Cisco IOS Software H.323 Denial of Service Vulnerabilities (cisco-sa-20100922-h323)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The H.323 implementation in Cisco IOS Software contains two
vulnerabilities that may be exploited remotely to cause a denial of
service (DoS) condition on a device that is running a vulnerable
version of Cisco IOS Software. Cisco has released free software
updates that address these vulnerabilities. There are no workarounds
to mitigate these vulnerabilities other than disabling H.323 on the
vulnerable device."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100922-h323
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bc2225b"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100922-h323."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/22");

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
if ( version == '12.1(3)XI' ) flag++;
if ( version == '12.1(3)XQ1' ) flag++;
if ( version == '12.1(3a)XI8' ) flag++;
if ( version == '12.1(3a)XI9' ) flag++;
if ( version == '12.1(3a)XL3' ) flag++;
if ( version == '12.1(5)T10' ) flag++;
if ( version == '12.1(5)T2' ) flag++;
if ( version == '12.1(5)T8a' ) flag++;
if ( version == '12.1(5)T9' ) flag++;
if ( version == '12.1(5)XM4' ) flag++;
if ( version == '12.1(5)XR1' ) flag++;
if ( version == '12.1(5)XS4' ) flag++;
if ( version == '12.1(5)XS5' ) flag++;
if ( version == '12.1(5)XU' ) flag++;
if ( version == '12.1(5)YA2' ) flag++;
if ( version == '12.1(5)YD6' ) flag++;
if ( version == '12.1(5)YF2' ) flag++;
if ( version == '12.2(1)M0' ) flag++;
if ( version == '12.2(11)T5' ) flag++;
if ( version == '12.2(11)T8' ) flag++;
if ( version == '12.2(12e)' ) flag++;
if ( version == '12.2(13)T10' ) flag++;
if ( version == '12.2(13)T2' ) flag++;
if ( version == '12.2(13)T5' ) flag++;
if ( version == '12.2(13)T8' ) flag++;
if ( version == '12.2(13)ZH5' ) flag++;
if ( version == '12.2(13)ZH9' ) flag++;
if ( version == '12.2(14)S11' ) flag++;
if ( version == '12.2(14)S7' ) flag++;
if ( version == '12.2(14)SU1' ) flag++;
if ( version == '12.2(15)CZ1' ) flag++;
if ( version == '12.2(15)MC1b' ) flag++;
if ( version == '12.2(15)MC1c' ) flag++;
if ( version == '12.2(15)ZJ2' ) flag++;
if ( version == '12.2(16)B1' ) flag++;
if ( version == '12.2(17d)SXB6' ) flag++;
if ( version == '12.2(18)SV3' ) flag++;
if ( version == '12.2(18)SXD1' ) flag++;
if ( version == '12.2(19b)' ) flag++;
if ( version == '12.2(1a)XC1' ) flag++;
if ( version == '12.2(2)T1' ) flag++;
if ( version == '12.2(2)T4' ) flag++;
if ( version == '12.2(2)XA2' ) flag++;
if ( version == '12.2(2)XB11' ) flag++;
if ( version == '12.2(2)XG1' ) flag++;
if ( version == '12.2(2)XQ' ) flag++;
if ( version == '12.2(2)XT2' ) flag++;
if ( version == '12.2(2)YC1' ) flag++;
if ( version == '12.2(2)YC4' ) flag++;
if ( version == '12.2(20)S10' ) flag++;
if ( version == '12.2(22)S2' ) flag++;
if ( version == '12.2(22)SV1' ) flag++;
if ( version == '12.2(24b)' ) flag++;
if ( version == '12.2(25)SW2' ) flag++;
if ( version == '12.2(25)SW9' ) flag++;
if ( version == '12.2(27)SBB4e' ) flag++;
if ( version == '12.2(27)SBC2' ) flag++;
if ( version == '12.2(27)SBC3' ) flag++;
if ( version == '12.2(28)SB10' ) flag++;
if ( version == '12.2(28)SB11' ) flag++;
if ( version == '12.2(28)SB13' ) flag++;
if ( version == '12.2(28)SB5c' ) flag++;
if ( version == '12.2(29)SV3' ) flag++;
if ( version == '12.2(31)SB3x' ) flag++;
if ( version == '12.2(31)SB5' ) flag++;
if ( version == '12.2(33)SB3' ) flag++;
if ( version == '12.2(33)SCB' ) flag++;
if ( version == '12.2(33)SCB6' ) flag++;
if ( version == '12.2(33)SRC2' ) flag++;
if ( version == '12.2(33)SRD6' ) flag++;
if ( version == '12.2(33)SRD7' ) flag++;
if ( version == '12.2(33)XNE' ) flag++;
if ( version == '12.2(33)XNE1' ) flag++;
if ( version == '12.2(4)BW1a' ) flag++;
if ( version == '12.2(4)XM3' ) flag++;
if ( version == '12.2(4)XV1' ) flag++;
if ( version == '12.2(4)XV2' ) flag++;
if ( version == '12.2(4)XV4' ) flag++;
if ( version == '12.2(4)YA3' ) flag++;
if ( version == '12.2(4)YA6' ) flag++;
if ( version == '12.2(8)T8' ) flag++;
if ( version == '12.2(8)YD3' ) flag++;
if ( version == '12.2(8)YL' ) flag++;
if ( version == '12.2(8)YY4' ) flag++;
if ( version == '12.2(8)ZB2' ) flag++;
if ( version == '12.2(8)ZB3' ) flag++;
if ( version == '12.3(11)YF2' ) flag++;
if ( version == '12.3(14)YM12' ) flag++;
if ( version == '12.3(14)YM3' ) flag++;
if ( version == '12.3(14)YM4' ) flag++;
if ( version == '12.3(14)YQ4' ) flag++;
if ( version == '12.3(14)YQ5' ) flag++;
if ( version == '12.3(14)YX10' ) flag++;
if ( version == '12.3(14)YX8' ) flag++;
if ( version == '12.3(2)T9' ) flag++;
if ( version == '12.3(2)XA4' ) flag++;
if ( version == '12.3(3)B1' ) flag++;
if ( version == '12.3(4)T2a' ) flag++;
if ( version == '12.3(4)T9' ) flag++;
if ( version == '12.3(4)XD1' ) flag++;
if ( version == '12.3(4)XD4' ) flag++;
if ( version == '12.3(4)XK3' ) flag++;
if ( version == '12.3(7)XI7' ) flag++;
if ( version == '12.3(8)T6' ) flag++;
if ( version == '12.3(8)T9' ) flag++;
if ( version == '12.3(8)XY3' ) flag++;
if ( version == '12.4(11)MR' ) flag++;
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
if ( version == '12.4(12)MR' ) flag++;
if ( version == '12.4(12)MR1' ) flag++;
if ( version == '12.4(12)MR2' ) flag++;
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
if ( version == '12.4(15)XL' ) flag++;
if ( version == '12.4(15)XL1' ) flag++;
if ( version == '12.4(15)XL2' ) flag++;
if ( version == '12.4(15)XL3' ) flag++;
if ( version == '12.4(15)XL4' ) flag++;
if ( version == '12.4(15)XL5' ) flag++;
if ( version == '12.4(15)XM1' ) flag++;
if ( version == '12.4(15)XM2' ) flag++;
if ( version == '12.4(15)XY' ) flag++;
if ( version == '12.4(15)XY1' ) flag++;
if ( version == '12.4(15)XY2' ) flag++;
if ( version == '12.4(15)XY3' ) flag++;
if ( version == '12.4(15)XY4' ) flag++;
if ( version == '12.4(15)XY5' ) flag++;
if ( version == '12.4(15)XZ' ) flag++;
if ( version == '12.4(15)XZ1' ) flag++;
if ( version == '12.4(15)XZ2' ) flag++;
if ( version == '12.4(16)MR' ) flag++;
if ( version == '12.4(16)MR1' ) flag++;
if ( version == '12.4(16)MR2' ) flag++;
if ( version == '12.4(18b)' ) flag++;
if ( version == '12.4(18e)' ) flag++;
if ( version == '12.4(19)MR' ) flag++;
if ( version == '12.4(19)MR1' ) flag++;
if ( version == '12.4(19)MR2' ) flag++;
if ( version == '12.4(2)XA' ) flag++;
if ( version == '12.4(2)XA1' ) flag++;
if ( version == '12.4(2)XA2' ) flag++;
if ( version == '12.4(2)XB1' ) flag++;
if ( version == '12.4(2)XB6' ) flag++;
if ( version == '12.4(20)MR' ) flag++;
if ( version == '12.4(20)MR2' ) flag++;
if ( version == '12.4(20)MRA' ) flag++;
if ( version == '12.4(20)T' ) flag++;
if ( version == '12.4(20)T1' ) flag++;
if ( version == '12.4(20)T2' ) flag++;
if ( version == '12.4(20)T3' ) flag++;
if ( version == '12.4(20)T4' ) flag++;
if ( version == '12.4(20)T5' ) flag++;
if ( version == '12.4(20)T5a' ) flag++;
if ( version == '12.4(20)YA' ) flag++;
if ( version == '12.4(20)YA1' ) flag++;
if ( version == '12.4(20)YA2' ) flag++;
if ( version == '12.4(20)YA3' ) flag++;
if ( version == '12.4(22)GC1' ) flag++;
if ( version == '12.4(22)T' ) flag++;
if ( version == '12.4(22)T1' ) flag++;
if ( version == '12.4(22)T2' ) flag++;
if ( version == '12.4(22)T3' ) flag++;
if ( version == '12.4(22)T5' ) flag++;
if ( version == '12.4(22)YB' ) flag++;
if ( version == '12.4(22)YB1' ) flag++;
if ( version == '12.4(22)YB4' ) flag++;
if ( version == '12.4(22)YB5' ) flag++;
if ( version == '12.4(22)YB6' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(4)T8' ) flag++;
if ( version == '12.4(4)XC' ) flag++;
if ( version == '12.4(4)XC1' ) flag++;
if ( version == '12.4(4)XC2' ) flag++;
if ( version == '12.4(4)XC3' ) flag++;
if ( version == '12.4(4)XC4' ) flag++;
if ( version == '12.4(4)XC5' ) flag++;
if ( version == '12.4(4)XC6' ) flag++;
if ( version == '12.4(4)XC7' ) flag++;
if ( version == '12.4(4)XD4' ) flag++;
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
if ( version == '12.4(6)T6' ) flag++;
if ( version == '12.4(6)T7' ) flag++;
if ( version == '12.4(6)T8' ) flag++;
if ( version == '12.4(6)T9' ) flag++;
if ( version == '12.4(6)XE' ) flag++;
if ( version == '12.4(6)XE1' ) flag++;
if ( version == '12.4(6)XE2' ) flag++;
if ( version == '12.4(6)XE3' ) flag++;
if ( version == '12.4(6)XP' ) flag++;
if ( version == '12.4(6)XT' ) flag++;
if ( version == '12.4(6)XT1' ) flag++;
if ( version == '12.4(6)XT2' ) flag++;
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
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"H323", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
