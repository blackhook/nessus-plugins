#TRUSTED 92623ff08163a0b4fef62e23f2321858eceef4e67fc83fa4bd9c46922d60891bfc35f76ebc8b36c225448e1068710df8adde132c179a39c29c72c595fa3eea15bee0f8bf039b6a465c84f378056467233480da1dbef225bd12ccf9400f7dd12f848f207f626e754f467b0d413924c4a882a555906c1fafcb9c50595316a8d97913ed4ed22c641901a8a823b2560990c0a00bdb061251d0ef934a781ac2fd14aab1340435155536da7d8cd693a1000aa0d6a6f97c4677f1d6b6091bc9826ec03d4fe88d2b4f7dd1d64dd9f9bdc85b381fcd10ab977abe7fd4d1e197045f1dbe41c8507bf49052d5cf0afa65866f1fe144134eb137376694842c39643d5eb9a445c561230a635426982a02fe647b16bfe9cd97debb5361f41024a8c4d4550bbaac6c2b85fa912375bbd7c13b9be66f0d92ec0e55d7241d8aa0a73967af6221670791b12cffef4788369172037174914d29835acd5be3e56eb286da2fdbbd2a86c5704d912e414513a4215482d7e042ca0dd2ce97abe922856536a5c3cdd0c4c30ee8ad6852a433e927bd833dbdd9a0105cfb1320d16a7b90a8e1c3ba47e22d07f59ce35356fb1ab073f3e8bd6e82e1a10495df8bbd2b771de20bf2e3c796c1d6ac37b37d296b9ca655cf3d74047733eaa3b9f75c817e6af6106e56d3693d3bd80a3ca572be8d1a0c2d0c8e79ba372445f12f2cbc450790e468f3220f62036bfc00
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20100922-sip.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(49648);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2009-2051", "CVE-2010-2835");
  script_bugtraq_id(36152);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsz43987");
  script_xref(name:"CISCO-BUG-ID", value:"CSCta20040");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100922-sip");

  script_name(english:"Cisco IOS Software Session Initiation Protocol Denial of Service Vulnerabilities (cisco-sa-20100922-sip)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities exist in the Session Initiation Protocol
(SIP) implementation in Cisco IOS Software that could allow an
unauthenticated, remote attacker to cause a reload of an affected
device when SIP operation is enabled. Cisco has released free software
updates that address these vulnerabilities. There are no workarounds
for devices that must run SIP; however, mitigations are available to
limit exposure to the vulnerabilities."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100922-sip
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07dc0162"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100922-sip."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
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
if ( version == '12.2(33)XNE' ) flag++;
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
if ( version == '12.3(11)XL' ) flag++;
if ( version == '12.3(11)XL1' ) flag++;
if ( version == '12.3(11)XL2' ) flag++;
if ( version == '12.3(11)XL3' ) flag++;
if ( version == '12.3(11)YF' ) flag++;
if ( version == '12.3(11)YF1' ) flag++;
if ( version == '12.3(11)YF2' ) flag++;
if ( version == '12.3(11)YF3' ) flag++;
if ( version == '12.3(11)YF4' ) flag++;
if ( version == '12.3(11)YK' ) flag++;
if ( version == '12.3(11)YK1' ) flag++;
if ( version == '12.3(11)YK2' ) flag++;
if ( version == '12.3(11)YL' ) flag++;
if ( version == '12.3(11)YL1' ) flag++;
if ( version == '12.3(11)YL2' ) flag++;
if ( version == '12.3(11)YN' ) flag++;
if ( version == '12.3(11)YR' ) flag++;
if ( version == '12.3(11)YR1' ) flag++;
if ( version == '12.3(11)YS2' ) flag++;
if ( version == '12.3(11)YW' ) flag++;
if ( version == '12.3(11)YW1' ) flag++;
if ( version == '12.3(11)YW2' ) flag++;
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
if ( version == '12.3(2)XF' ) flag++;
if ( version == '12.3(4)XD' ) flag++;
if ( version == '12.3(4)XD1' ) flag++;
if ( version == '12.3(4)XD2' ) flag++;
if ( version == '12.3(4)XD3' ) flag++;
if ( version == '12.3(4)XD4' ) flag++;
if ( version == '12.3(4)XG' ) flag++;
if ( version == '12.3(4)XG1' ) flag++;
if ( version == '12.3(4)XG2' ) flag++;
if ( version == '12.3(4)XG3' ) flag++;
if ( version == '12.3(4)XG4' ) flag++;
if ( version == '12.3(4)XG5' ) flag++;
if ( version == '12.3(4)XH' ) flag++;
if ( version == '12.3(4)XH1' ) flag++;
if ( version == '12.3(4)XK' ) flag++;
if ( version == '12.3(4)XK1' ) flag++;
if ( version == '12.3(4)XK2' ) flag++;
if ( version == '12.3(4)XK3' ) flag++;
if ( version == '12.3(4)XK4' ) flag++;
if ( version == '12.3(4)XQ' ) flag++;
if ( version == '12.3(4)XQ1' ) flag++;
if ( version == '12.3(7)T' ) flag++;
if ( version == '12.3(7)T1' ) flag++;
if ( version == '12.3(7)T10' ) flag++;
if ( version == '12.3(7)T11' ) flag++;
if ( version == '12.3(7)T12' ) flag++;
if ( version == '12.3(7)T2' ) flag++;
if ( version == '12.3(7)T3' ) flag++;
if ( version == '12.3(7)T4' ) flag++;
if ( version == '12.3(7)T5' ) flag++;
if ( version == '12.3(7)T6' ) flag++;
if ( version == '12.3(7)T7' ) flag++;
if ( version == '12.3(7)T8' ) flag++;
if ( version == '12.3(7)T9' ) flag++;
if ( version == '12.3(7)XI' ) flag++;
if ( version == '12.3(7)XI10a' ) flag++;
if ( version == '12.3(7)XI2' ) flag++;
if ( version == '12.3(7)XI2b' ) flag++;
if ( version == '12.3(7)XI3' ) flag++;
if ( version == '12.3(7)XI4' ) flag++;
if ( version == '12.3(7)XI5' ) flag++;
if ( version == '12.3(7)XI6' ) flag++;
if ( version == '12.3(7)XI7' ) flag++;
if ( version == '12.3(7)XI7a' ) flag++;
if ( version == '12.3(7)XI7b' ) flag++;
if ( version == '12.3(7)XI8' ) flag++;
if ( version == '12.3(7)XI8bc' ) flag++;
if ( version == '12.3(7)XI8g' ) flag++;
if ( version == '12.3(7)XJ' ) flag++;
if ( version == '12.3(7)XJ1' ) flag++;
if ( version == '12.3(7)XJ2' ) flag++;
if ( version == '12.3(7)XL' ) flag++;
if ( version == '12.3(7)XM' ) flag++;
if ( version == '12.3(7)XR' ) flag++;
if ( version == '12.3(7)XR3' ) flag++;
if ( version == '12.3(7)XR4' ) flag++;
if ( version == '12.3(7)XR5' ) flag++;
if ( version == '12.3(7)XR6' ) flag++;
if ( version == '12.3(7)XR7' ) flag++;
if ( version == '12.3(7)YB' ) flag++;
if ( version == '12.3(7)YB1' ) flag++;
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
if ( version == '12.3(8)XX' ) flag++;
if ( version == '12.3(8)XX1' ) flag++;
if ( version == '12.3(8)XX2d' ) flag++;
if ( version == '12.3(8)XX2e' ) flag++;
if ( version == '12.3(8)XY' ) flag++;
if ( version == '12.3(8)XY1' ) flag++;
if ( version == '12.3(8)XY2' ) flag++;
if ( version == '12.3(8)XY3' ) flag++;
if ( version == '12.3(8)XY4' ) flag++;
if ( version == '12.3(8)XY5' ) flag++;
if ( version == '12.3(8)XY6' ) flag++;
if ( version == '12.3(8)XY7' ) flag++;
if ( version == '12.3(8)YC' ) flag++;
if ( version == '12.3(8)YC1' ) flag++;
if ( version == '12.3(8)YC2' ) flag++;
if ( version == '12.3(8)YC3' ) flag++;
if ( version == '12.3(8)YG' ) flag++;
if ( version == '12.3(8)YG2' ) flag++;
if ( version == '12.3(8)YG3' ) flag++;
if ( version == '12.3(8)YG4' ) flag++;
if ( version == '12.3(8)YG6' ) flag++;
if ( version == '12.3(8)ZA' ) flag++;
if ( version == '12.3(8)ZA1' ) flag++;
if ( version == '12.4(1)' ) flag++;
if ( version == '12.4(10)' ) flag++;
if ( version == '12.4(10a)' ) flag++;
if ( version == '12.4(10b)' ) flag++;
if ( version == '12.4(10c)' ) flag++;
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
if ( version == '12.4(20)T5' ) flag++;
if ( version == '12.4(20)T5a' ) flag++;
if ( version == '12.4(20)YA' ) flag++;
if ( version == '12.4(20)YA1' ) flag++;
if ( version == '12.4(20)YA2' ) flag++;
if ( version == '12.4(20)YA3' ) flag++;
if ( version == '12.4(21)' ) flag++;
if ( version == '12.4(21a)' ) flag++;
if ( version == '12.4(21a)M1' ) flag++;
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
if ( version == '12.4(23)' ) flag++;
if ( version == '12.4(23a)' ) flag++;
if ( version == '12.4(23b)' ) flag++;
if ( version == '12.4(23b)M1' ) flag++;
if ( version == '12.4(23c)' ) flag++;
if ( version == '12.4(23d)' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
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
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SIP", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
