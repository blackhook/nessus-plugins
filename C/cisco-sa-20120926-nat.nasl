#TRUSTED b0c2fd8f3df96da0cfde73ca7202c26ce81b2fc94247d6881287c79c0d203943752d172baffd68e0825546093289683a4110ba1188e73cec5c4c439b899685bf7c35d5dfcde4ad7d66bbca691ab8c3c08f52198e995f6de27161577d63db9df44e3042e1b898ae443eca8370b0a6e67b14617302244cedf41faf99443058210c29cea9776e4cae5f4b06f7ec9c669322ef93cfd113695ea678c24e00e8b9bc8fc3c0ba66f982c65ce1861e6f8764a8b139842ab7608ffde1c0ce568dffc247cd25df52bf8663bfd8fa673bd1d0dbb9de66a8e80be998ea568e6c5c8c6082186c1dc602dc9441d822f32dcf52ebb48c119c4856cebcc63d0b1acad390cca5b78496e96eef826ca43a74edff7d0eb8205234883f75900c94bbadce78d5dee34e8f1cb12b23a4b9f98ee495e38f5647c08f2b5f7ff9f1f7531c4f737b6dc82603c46576c8d890105e56fbfddcc933cb5f5d70377920c2d4fda963013ef9f49a16b68e038f235560f3e57c0fe0a9034497f92da525119ef32462c0b7cb087ce79757b0e203516246e083f017ae790103bae4688528ed61d6c351801c060d98ac995e7317eb6fe953389613ce40153ceefdfcf8e2ffdbb5b5be1b42b95b88dfaa8fa1bf0579cc55451495a1ac6dba5c86550e309a6fda42a30167747af0813e3a4943e1360470e75c7c669b0d485f52acf543e9deee4a504298aa729de3431639826e
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120926-nat.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(62375);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2012-4618", "CVE-2012-4619");
  script_bugtraq_id(55693, 55705);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtn76183");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtr46123");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120926-nat");

  script_name(english:"Cisco IOS Software Network Address Translation Vulnerabilities (cisco-sa-20120926-nat)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS Software Network Address Translation (NAT) feature
contains two denial of service (DoS) vulnerabilities in the
translation of IP packets. The vulnerabilities are caused when packets
in transit on the vulnerable device require translation. Cisco has
released free software updates that address these vulnerabilities."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120926-nat
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97b2e3bb"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120926-nat."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/28");

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
if ( version == '12.2(33)SXH7w' ) flag++;
if ( version == '12.2(33)SXH8' ) flag++;
if ( version == '12.2(33)SXH8a' ) flag++;
if ( version == '12.2(33)SXH8b' ) flag++;
if ( version == '12.2(33)SXI5' ) flag++;
if ( version == '12.2(33)SXI5a' ) flag++;
if ( version == '12.2(33)SXI6' ) flag++;
if ( version == '12.2(33)SXJ' ) flag++;
if ( version == '12.2(50)SY' ) flag++;
if ( version == '12.2(50)SY1' ) flag++;
if ( version == '12.2(50)SY2' ) flag++;
if ( version == '12.4(15)T13' ) flag++;
if ( version == '12.4(15)T13b' ) flag++;
if ( version == '12.4(15)T14' ) flag++;
if ( version == '12.4(15)T15' ) flag++;
if ( version == '12.4(15)T16' ) flag++;
if ( version == '12.4(15)T17' ) flag++;
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
if ( version == '12.4(24)MD' ) flag++;
if ( version == '12.4(24)MD1' ) flag++;
if ( version == '12.4(24)MD2' ) flag++;
if ( version == '12.4(24)MD3' ) flag++;
if ( version == '12.4(24)MD4' ) flag++;
if ( version == '12.4(24)MD5' ) flag++;
if ( version == '12.4(24)MD6' ) flag++;
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
if ( version == '12.4(24)MDB1' ) flag++;
if ( version == '12.4(24)MDB3' ) flag++;
if ( version == '12.4(24)MDB4' ) flag++;
if ( version == '12.4(24)MDB5' ) flag++;
if ( version == '12.4(24)MDB5a' ) flag++;
if ( version == '12.4(24)MDB6' ) flag++;
if ( version == '12.4(24)MDB7' ) flag++;
if ( version == '12.4(24)MDB8' ) flag++;
if ( version == '12.4(24)MDB9' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(24)T31f' ) flag++;
if ( version == '12.4(24)T32f' ) flag++;
if ( version == '12.4(24)T33f' ) flag++;
if ( version == '12.4(24)T35c' ) flag++;
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
if ( version == '12.4(24)T5' ) flag++;
if ( version == '12.4(24)T6' ) flag++;
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
if ( version == '12.4(25)' ) flag++;
if ( version == '12.4(25a)' ) flag++;
if ( version == '12.4(25b)' ) flag++;
if ( version == '12.4(25c)' ) flag++;
if ( version == '12.4(25d)' ) flag++;
if ( version == '12.4(25e)' ) flag++;
if ( version == '12.4(25f)' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)M6a' ) flag++;
if ( version == '15.0(1)M7' ) flag++;
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
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;
if ( version == '15.1(4)XB5a' ) flag++;
if ( version == '15.1(4)XB6' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(1)T2' ) flag++;
if ( version == '15.2(2)T' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip\s*nat\s*enable", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ip\s*nat\s*inside", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ip\s*nat\s*outside", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
