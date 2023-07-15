#TRUSTED 76081caeb944c59f18e453106298be92f84ae5516b29c1819e8157b97b6fb19a0226ce2e0766d82e3dd85794a766dcb14f37c20208ee1478f3171cd0340da9b4cc17218a2e97bf2431e4eb567a5da46d4b75baac0a921f2fa874948086ad65e2530e2f66dc5cba0c3563c168cb36bccba2f5428b9bd84355bd7f3dc082fa7d6662e0e5481fe99996d138d8f99566f20c7b11b4fc5db08e1d8d4a5bf35ca489dbf5699b99a1282dd413d74531871578bc1f76d2cc105b5328c8987d3745336c966cd9f9da1b4087e4124f2b1a073b438d2c1e02b9dc9227d075e2f8ebff204ff2b35f0b57e76db0b07d6925897d4b08a2e6b65fd38acd97210c0000b915d96218cf32b2406c9016c9a089e7a9dc7360ae487311677dfc77452b340f5b7dabb349226d4358c182bb7b7726bbde062a938fd6f183e657355c941d6d3169aeea5b3ef4ec231cb5cd7c6942a182b581d53d26c66f8a18c76533dfe06be2028d4ec150382a7349d7d2ade8a8569e3bb4ba38f4e5a4ebad42df5ced6b220ee09ad42e23533c247a2513df83b11e61f7ad3cc352614e382144e268b247290b54b711b025af6c01d3b73818a3d7a3a5c46768a2ce60b7eaefa56737385042c7b56fcb85cb29608ade65fb0e5342f7c859ebed314bf7b72a45bfa03ebae313772dd5c630469995a11d3c2a3ec69fcb1a1ac34dc920185ed5f782a98d1f611f1847326d76f0
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00807d3715.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48999);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2007-0648");
 script_bugtraq_id(22330);
 script_xref(name:"CERT", value:"438176");
 script_name(english:"SIP Packets Reload IOS Devices with support for SIP");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco devices running an affected version of Internetwork Operating
System (IOS) which supports Session Initiation Protocol (SIP) are
affected by a vulnerability that may lead to a reload of the device
when receiving a specific series of packets destined to port 5060. This
issue is compounded by a related bug which allows traffic to TCP 5060
and UDP port 5060 on devices not configured for SIP.
There are no known instances of intentional exploitation of this issue.
However, Cisco has observed data streams that appear to be
unintentionally triggering the vulnerability.
Workarounds exist to mitigate the effects of this problem on devices
which do not require SIP.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?063af0ee");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00807d3715.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?4dfc145d");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070131-sip.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/31");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/01/31");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsb25337");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsh58082");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20070131-sip");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2018 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.4(6)XT') flag++;
else if (version == '12.4(6)XP') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(4)XD7') flag++;
else if (version == '12.4(4)XD5') flag++;
else if (version == '12.4(4)XD4') flag++;
else if (version == '12.4(4)XD2') flag++;
else if (version == '12.4(4)XD1') flag++;
else if (version == '12.4(4)XD') flag++;
else if (version == '12.4(4)XC5') flag++;
else if (version == '12.4(4)XC4') flag++;
else if (version == '12.4(4)XC3') flag++;
else if (version == '12.4(4)XC2') flag++;
else if (version == '12.4(4)XC1') flag++;
else if (version == '12.4(4)XC') flag++;
else if (version == '12.4(2)XB5') flag++;
else if (version == '12.4(2)XB4') flag++;
else if (version == '12.4(2)XB3') flag++;
else if (version == '12.4(2)XB2') flag++;
else if (version == '12.4(2)XB1') flag++;
else if (version == '12.4(2)XB') flag++;
else if (version == '12.4(2)XA2') flag++;
else if (version == '12.4(2)XA1') flag++;
else if (version == '12.4(2)XA') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T2') flag++;
else if (version == '12.4(9)T1') flag++;
else if (version == '12.4(9)T') flag++;
else if (version == '12.4(6)T6') flag++;
else if (version == '12.4(6)T5') flag++;
else if (version == '12.4(6)T4') flag++;
else if (version == '12.4(6)T3') flag++;
else if (version == '12.4(6)T2') flag++;
else if (version == '12.4(6)T1') flag++;
else if (version == '12.4(6)T') flag++;
else if (version == '12.4(4)T7') flag++;
else if (version == '12.4(4)T6') flag++;
else if (version == '12.4(4)T5') flag++;
else if (version == '12.4(4)T4') flag++;
else if (version == '12.4(4)T3') flag++;
else if (version == '12.4(4)T2') flag++;
else if (version == '12.4(4)T1') flag++;
else if (version == '12.4(4)T') flag++;
else if (version == '12.4(2)T5') flag++;
else if (version == '12.4(2)T4') flag++;
else if (version == '12.4(2)T3') flag++;
else if (version == '12.4(2)T2') flag++;
else if (version == '12.4(2)T1') flag++;
else if (version == '12.4(2)T') flag++;
else if (version == '12.4(11)MR') flag++;
else if (version == '12.4(9)MR') flag++;
else if (version == '12.4(6)MR1') flag++;
else if (version == '12.4(6)MR') flag++;
else if (version == '12.4(4)MR1') flag++;
else if (version == '12.4(4)MR') flag++;
else if (version == '12.4(2)MR1') flag++;
else if (version == '12.4(2)MR') flag++;
else if (version == '12.4(12)') flag++;
else if (version == '12.4(10b)') flag++;
else if (version == '12.4(10a)') flag++;
else if (version == '12.4(10)') flag++;
else if (version == '12.4(8c)') flag++;
else if (version == '12.4(8b)') flag++;
else if (version == '12.4(8a)') flag++;
else if (version == '12.4(8)') flag++;
else if (version == '12.4(7d)') flag++;
else if (version == '12.4(7c)') flag++;
else if (version == '12.4(7b)') flag++;
else if (version == '12.4(7a)') flag++;
else if (version == '12.4(7)') flag++;
else if (version == '12.4(5b)') flag++;
else if (version == '12.4(5a)') flag++;
else if (version == '12.4(5)') flag++;
else if (version == '12.4(3g)') flag++;
else if (version == '12.4(3f)') flag++;
else if (version == '12.4(3e)') flag++;
else if (version == '12.4(3d)') flag++;
else if (version == '12.4(3c)') flag++;
else if (version == '12.4(3b)') flag++;
else if (version == '12.4(3a)') flag++;
else if (version == '12.4(3)') flag++;
else if (version == '12.4(1c)') flag++;
else if (version == '12.4(1b)') flag++;
else if (version == '12.4(1a)') flag++;
else if (version == '12.4(1)') flag++;
else if (version == '12.3(8)ZA') flag++;
else if (version == '12.3(11)YZ1') flag++;
else if (version == '12.3(11)YZ') flag++;
else if (version == '12.3(14)YX5') flag++;
else if (version == '12.3(14)YX4') flag++;
else if (version == '12.3(14)YX3') flag++;
else if (version == '12.3(14)YX2') flag++;
else if (version == '12.3(14)YX1') flag++;
else if (version == '12.3(14)YX') flag++;
else if (version == '12.3(14)YU1') flag++;
else if (version == '12.3(14)YU') flag++;
else if (version == '12.3(14)YT1') flag++;
else if (version == '12.3(14)YT') flag++;
else if (version == '12.3(14)YQ8') flag++;
else if (version == '12.3(14)YQ7') flag++;
else if (version == '12.3(14)YQ6') flag++;
else if (version == '12.3(14)YQ5') flag++;
else if (version == '12.3(14)YQ4') flag++;
else if (version == '12.3(14)YQ3') flag++;
else if (version == '12.3(14)YQ2') flag++;
else if (version == '12.3(14)YQ1') flag++;
else if (version == '12.3(14)YQ') flag++;
else if (version == '12.3(14)YM9') flag++;
else if (version == '12.3(14)YM8') flag++;
else if (version == '12.3(14)YM7') flag++;
else if (version == '12.3(14)YM6') flag++;
else if (version == '12.3(14)YM5') flag++;
else if (version == '12.3(14)YM4') flag++;
else if (version == '12.3(14)YM3') flag++;
else if (version == '12.3(14)YM2') flag++;
else if (version == '12.3(11)YK2') flag++;
else if (version == '12.3(11)YK1') flag++;
else if (version == '12.3(11)YK') flag++;
else if (version == '12.3(8)YG4') flag++;
else if (version == '12.3(8)YG3') flag++;
else if (version == '12.3(8)YG2') flag++;
else if (version == '12.3(8)YG') flag++;
else if (version == '12.3(11)YF4') flag++;
else if (version == '12.3(11)YF3') flag++;
else if (version == '12.3(11)YF2') flag++;
else if (version == '12.3(11)YF1') flag++;
else if (version == '12.3(11)YF') flag++;
else if (version == '12.3(8)XY7') flag++;
else if (version == '12.3(8)XY6') flag++;
else if (version == '12.3(8)XY5') flag++;
else if (version == '12.3(8)XY4') flag++;
else if (version == '12.3(8)XY3') flag++;
else if (version == '12.3(8)XY2') flag++;
else if (version == '12.3(8)XY1') flag++;
else if (version == '12.3(8)XY') flag++;
else if (version == '12.3(8)XX2d') flag++;
else if (version == '12.3(8)XX1') flag++;
else if (version == '12.3(8)XX') flag++;
else if (version == '12.3(8)XW3') flag++;
else if (version == '12.3(8)XW2') flag++;
else if (version == '12.3(8)XW1') flag++;
else if (version == '12.3(8)XW') flag++;
else if (version == '12.3(8)XU5') flag++;
else if (version == '12.3(8)XU4') flag++;
else if (version == '12.3(8)XU3') flag++;
else if (version == '12.3(8)XU2') flag++;
else if (version == '12.3(7)XR6') flag++;
else if (version == '12.3(7)XR5') flag++;
else if (version == '12.3(7)XR4') flag++;
else if (version == '12.3(7)XR3') flag++;
else if (version == '12.3(7)XR') flag++;
else if (version == '12.3(4)XQ1') flag++;
else if (version == '12.3(4)XQ') flag++;
else if (version == '12.3(11)XL1') flag++;
else if (version == '12.3(11)XL') flag++;
else if (version == '12.3(14)T7') flag++;
else if (version == '12.3(14)T6') flag++;
else if (version == '12.3(14)T5') flag++;
else if (version == '12.3(14)T3') flag++;
else if (version == '12.3(14)T2') flag++;
else if (version == '12.3(14)T1') flag++;
else if (version == '12.3(14)T') flag++;
else if (version == '12.3(11)T9') flag++;
else if (version == '12.3(11)T8') flag++;
else if (version == '12.3(11)T7') flag++;
else if (version == '12.3(11)T6') flag++;
else if (version == '12.3(11)T5') flag++;
else if (version == '12.3(11)T4') flag++;
else if (version == '12.3(11)T3') flag++;
else if (version == '12.3(11)T2') flag++;
else if (version == '12.3(11)T11') flag++;
else if (version == '12.3(11)T10') flag++;
else if (version == '12.3(11)T') flag++;
else if (version == '12.3(8)T9') flag++;
else if (version == '12.3(8)T8') flag++;
else if (version == '12.3(8)T7') flag++;
else if (version == '12.3(8)T6') flag++;
else if (version == '12.3(8)T5') flag++;
else if (version == '12.3(8)T4') flag++;
else if (version == '12.3(8)T3') flag++;
else if (version == '12.3(8)T11') flag++;
else if (version == '12.3(8)T10') flag++;
else if (version == '12.3(8)T1') flag++;
else if (version == '12.3(8)T') flag++;

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

