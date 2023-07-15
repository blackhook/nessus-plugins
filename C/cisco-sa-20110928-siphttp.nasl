#TRUSTED acf9cd3ffb6b5fb361a5301d1332af6518d0a33a81ad324110f9156a5564eee073ad542275972bf4b359a8b6e388b049798ca6ef96d79e855186d7dfd7bc8cc42a113b1e0f0127eb504fdba9cf051c30d9a7ef3140b5468353bbadd8819dc78f5e9f05fca9066073660fa9abd9697c407abdf41cd333ece30ab7be6d8e75f926bd751f4ac90a59158c0ac4fa76969ad0c0f7406908fc05a6e7fafb243d9c5918c57435980c6b1799de29445d9a177b8123e786d6cbc1789bf9be72d3e79dc0e814238b819a3426cb3f6e91ac9677fdc25dfba0e3e6be639b80e3cc524d434ada7ef913eab904ef3a291988d22380f5af51cfe5f9c35e89cdb5030d39f125173435769fb65563b94691b5222faab1c67ce0c74a5fcc2b23b35ec602130ba9b6b278c01c7570bce37b439dfa71e7f96e06bb514ae1eef0b63c6c0fd97b24928f2e82c508a5649ceb91158f12009821a2ed869af8e063375ca5a528289e3a8d88da182e2a6b09c6dc0b9886d6dcc0bdbb6183bf1d3249025f99052e504fb3b794f8e409238820a81eae643b890cd90771896ef07a3f0a9df64104806c9f33641f67b577fcad874bfe2bb3e6b7af6a44721ea8eb268a82faf700a26dce6d9b4edd8190a8f103a609ac4161d997a5c0a56fd0bb80296a5fdf2dffe9cef8e9cc10d2da9d36f8398a81ebfd09460ee78d7fa4c8791e2b246c3538826836d089dfd3cf67
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20110928-sip.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(56319);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2011-0939", "CVE-2011-2072", "CVE-2011-3275");
  script_xref(name:"CISCO-BUG-ID", value:"CSCth03022");
  script_xref(name:"CISCO-BUG-ID", value:"CSCti48504");
  script_xref(name:"CISCO-BUG-ID", value:"CSCto88686");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110928-sip");

  script_name(english:"Cisco IOS Software Session Initiation Protocol Denial of Service Vulnerabilities (cisco-sa-20110928-sip)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities exist in the Session Initiation Protocol
(SIP) implementation in Cisco IOS Software and Cisco IOS XE Software
that could allow an unauthenticated, remote attacker to cause a reload
of an affected device or trigger memory leaks that may result in
system instabilities. Affected devices would need to be configured to
process SIP messages for these vulnerabilities to be exploitable.
Cisco has released free software updates that address these
vulnerabilities. There are no workarounds for devices that must run
SIP; however, mitigations are available to limit exposure to the
vulnerabilities."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110928-sip
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45664e69"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110928-sip."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");
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
if ( version == '12.2(33)XNE1' ) flag++;
if ( version == '12.2(33)XNE1xb' ) flag++;
if ( version == '12.2(33)XNE2' ) flag++;
if ( version == '12.2(33)XNF' ) flag++;
if ( version == '12.2(33)XNF1' ) flag++;
if ( version == '12.2(33)XNF2' ) flag++;
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
if ( version == '12.4(15)T13b' ) flag++;
if ( version == '12.4(15)T14' ) flag++;
if ( version == '12.4(15)T15' ) flag++;
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
if ( version == '12.4(22)GC1' ) flag++;
if ( version == '12.4(22)GC1a' ) flag++;
if ( version == '12.4(22)T' ) flag++;
if ( version == '12.4(22)T1' ) flag++;
if ( version == '12.4(22)T2' ) flag++;
if ( version == '12.4(22)T3' ) flag++;
if ( version == '12.4(22)T4' ) flag++;
if ( version == '12.4(22)T5' ) flag++;
if ( version == '12.4(22)T6' ) flag++;
if ( version == '12.4(22)YB' ) flag++;
if ( version == '12.4(22)YB1' ) flag++;
if ( version == '12.4(22)YB4' ) flag++;
if ( version == '12.4(22)YB5' ) flag++;
if ( version == '12.4(22)YB6' ) flag++;
if ( version == '12.4(22)YB7' ) flag++;
if ( version == '12.4(22)YB8' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)GC3' ) flag++;
if ( version == '12.4(24)GC3a' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(24)T4' ) flag++;
if ( version == '12.4(24)T5' ) flag++;
if ( version == '12.4(4)XC' ) flag++;
if ( version == '12.4(4)XC1' ) flag++;
if ( version == '12.4(4)XC2' ) flag++;
if ( version == '12.4(4)XC3' ) flag++;
if ( version == '12.4(4)XC4' ) flag++;
if ( version == '12.4(4)XC5' ) flag++;
if ( version == '12.4(4)XC6' ) flag++;
if ( version == '12.4(4)XC7' ) flag++;
if ( version == '12.4(6)XE' ) flag++;
if ( version == '12.4(6)XE1' ) flag++;
if ( version == '12.4(6)XE2' ) flag++;
if ( version == '12.4(6)XE3' ) flag++;
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
if ( version == '12.4(9)XG2' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)S' ) flag++;
if ( version == '15.0(1)S1' ) flag++;
if ( version == '15.0(1)S2' ) flag++;
if ( version == '15.0(1)S3' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;
if ( version == '15.0(1)XA5' ) flag++;
if ( version == '15.0(1s)S2' ) flag++;
if ( version == '15.1(1)S' ) flag++;
if ( version == '15.1(1)S1' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)S' ) flag++;
if ( version == '15.1(2)S1' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
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
