#TRUSTED 288c22a480ae97e3b5581a5c5ddffc6a6c9680288321a4632ba43b35bd838a3889af87f7565f12ee43e6f30a31d507d440289f17420914b5dd4b1b83b73fd7ea9eaa52e2764c5bcb56398e020cdd66023ea611d868cc9b73ef21dd778bf445df8b3e47298a4401c45803ee46980116ecc74159af814e1f975f9b8415cab7b799baf4dcacc8ec6ebafd15f9d5cece000752171d098c23b431af7a565dc85687352c3214fe31cf4b9220494e80fc0888b8ae42a303d02824fb58160efd5b518bcfd4b8f90ef32019c32a6b57b58446fa0117c4b3c58485455d3d5e98d851b36acc68d38a6f4101c833975eee93bee9b15a20190fde2a6e90e5be99d69446cd989571752b87c2f1ec560dedf0592379fc5f95a1c93a47d1014d67b27e2a4be70fa02b5b6037c65359eea2616f56450d9e6a5fdbf56cbfb0f6c396a9447e6f685e74298f4c0934efe40a768fff11190f45bb243982300cf664a60bea66fa3a8fa985159d1d06a2437a95d87a9014cdb7be37117eaeff7081457095afe5813091147a17a75244eb0d69dbce81bf2225f904d8d8ac59a94306e5bf2c94e478148f539b8b8603d8b7ab93b1376917fa64fdf1afa0b73de260599cd09520a7e1f6ce5ed8548b7645b33aa83068481ca59e6db00bd72c6b28934adfea502f8945cbb8722e8f1c6af3c881d045153326fc0a7cd945252099d0e018b40380753418832376c9
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120926-ios-ips.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(62374);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2012-3950");
  script_bugtraq_id(55695);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtw55976");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120926-ios-ips");

  script_name(english:"Cisco IOS Software Intrusion Prevention System Denial of Service Vulnerability (cisco-sa-20120926-ios-ips)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a vulnerability in the Intrusion
Prevention System (IPS) feature that could allow an unauthenticated,
remote attacker to cause a reload of an affected device if specific
Cisco IOS IPS configurations exist. Cisco has released free software
updates that address this vulnerability. Workarounds that mitigate
this vulnerability are available."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120926-ios-ips
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1beca939"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120926-ios-ips."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
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
if ( version == '12.4(14)XK' ) flag++;
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
if ( version == '12.4(15)XF' ) flag++;
if ( version == '12.4(15)XY' ) flag++;
if ( version == '12.4(15)XY1' ) flag++;
if ( version == '12.4(15)XY2' ) flag++;
if ( version == '12.4(15)XY3' ) flag++;
if ( version == '12.4(15)XY4' ) flag++;
if ( version == '12.4(15)XY5' ) flag++;
if ( version == '12.4(15)XZ' ) flag++;
if ( version == '12.4(15)XZ1' ) flag++;
if ( version == '12.4(15)XZ2' ) flag++;
if ( version == '12.4(16)MR1' ) flag++;
if ( version == '12.4(16)MR2' ) flag++;
if ( version == '12.4(19)MR' ) flag++;
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
if ( version == '12.4(24)GC4' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(24)T4' ) flag++;
if ( version == '12.4(24)T5' ) flag++;
if ( version == '12.4(24)T6' ) flag++;
if ( version == '12.4(24)T7' ) flag++;
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
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
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
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(2)T' ) flag++;
if ( version == '15.2(2)T1' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)XA' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ips_signatures", "show ip ips signatures");
    if (check_cisco_result(buf))
    {
      m = eregmatch(pattern:".*6054:0\s+[^\s]+\s+([^\s]+).*", string:buf);
      if ( (!isnull(m)) && ("Y" >!< m[0]) ) { flag = 1; }

      m = eregmatch(pattern:".*6054:1\s+[^\s]+\s+([^\s]+).*", string:buf);
      if ( (!isnull(m)) && ("Y" >!< m[0]) ) { flag = 1; }

      m = eregmatch(pattern:".*6062:0\s+[^\s]+\s+([^\s]+).*", string:buf);
      if ( (!isnull(m)) && ("Y" >!< m[0]) ) { flag = 1; }

      m = eregmatch(pattern:".*6062:0\s+[^\s]+\s+([^\s]+).*", string:buf);
      if ( (!isnull(m)) && ("Y" >!< m[0]) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show ip ips configuration", "show ip ips configuration");
    if (check_cisco_result(buf))
    {
      m = eregmatch(pattern:"Category[ ]*configurations diag2:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*os general_os:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*attack general_attack:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*other_services general_service:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*l2/l3/l4_protocol/ip tcp:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*l2/l3/l4_protocol/ip udp:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*network_services dns:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*ios_ips basic:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }

      m = eregmatch(pattern:"Category[ ]*ios_ips advanced:(([\n\r ]*[^\r\n:]+: [^\n\r:]+)+)", string:buf);
      if ( (!isnull(m)) && ("Enable: True" >< m[1]) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
