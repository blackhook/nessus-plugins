#TRUSTED 31be66ceedf735c87908c2b2bbd51afd439bfb35aa4ffe676b977a9235eca84c9f386f955ab3108cffc7f77209b7d198df99351ec21fffc8c3da876e3cc79be3901fb06edc0db80480d8d4edbbacf88179b724affa4d519c14aa78dc696247ece5e9693084003fa100adcdc26c01607644c34ad486778eb71523f9335bce51b9c923f2000edefe3a5dc9b9fba1f2ea3ccc4bf0548c19c30fbdec61334cc4d0ce2aecfd208da75227da2a453560f6c1d2eaae41a8ee0a5ce2662cfbb530bdda31dcef8692c404585da54a708d6218b0a0fbf4bb785d2aea922c1eb967f9354e2ef40bc6f6b4e8a6ca0ee8bdce9e3383d07bd280e42d0b44527928f4071ed236622822833ad4529bbcf0007fef722e10e0c872e27167c635a8aa7b24e245942c9c23b1508796b2b702183da75bc359148cd7134d8a8291354656b4e205b13184fe1276c392c7bc87ff284e6a367d8dbd11349f3ceb26c54d3cb0494000aa071b63c01b5988056a37c1da80e1e3956f67e644e0f52e950498ec80a511307924bbe1b6edd3c8cf7741fc48354daab68e912167d85129f22591107552abf3c915e113a1d81065265659b479bbfad0d318f2bdd01ada1e191cf7407a87f8bcaa52737c23e5bb454560bd015282821cf055bcb318287f20c618a5636fcaceace63599c9df7f8334066bd4eb30c6f9ce8d0f624116b8aff1ba73545ce35fe6556c7810a4
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080a96c2a.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49029);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2009-0635");
 script_bugtraq_id(34246);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsr16693");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsu21828");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090325-ctcp");
 script_name(english:"Cisco IOS cTCP Denial of Service Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'A series of TCP packets may cause a denial of service (DoS) condition
on Cisco IOS devices that are configured as Easy VPN servers with the
Cisco Tunneling Control Protocol (cTCP) encapsulation feature. Cisco
has released free software updates that address this vulnerability. No
workarounds are available; however, the IPSec NAT traversal (NAT-T)
feature can be used as an alternative.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb2462c6");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080a96c2a.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?57f2c886");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090325-ctcp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/03/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
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
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(20)YA1') flag++;
else if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ1') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(15)XY5') flag++;
else if (version == '12.4(15)XY4') flag++;
else if (version == '12.4(15)XY3') flag++;
else if (version == '12.4(15)XY2') flag++;
else if (version == '12.4(15)XY1') flag++;
else if (version == '12.4(15)XY') flag++;
else if (version == '12.4(11)XW9') flag++;
else if (version == '12.4(11)XW8') flag++;
else if (version == '12.4(11)XW7') flag++;
else if (version == '12.4(11)XW6') flag++;
else if (version == '12.4(11)XW5') flag++;
else if (version == '12.4(11)XW4') flag++;
else if (version == '12.4(11)XW3') flag++;
else if (version == '12.4(11)XW2') flag++;
else if (version == '12.4(11)XW10') flag++;
else if (version == '12.4(11)XW1') flag++;
else if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(15)XF') flag++;
else if (version == '12.4(6)XE3') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(20)T1') flag++;
else if (version == '12.4(20)T') flag++;
else if (version == '12.4(15)T8') flag++;
else if (version == '12.4(15)T7') flag++;
else if (version == '12.4(15)T6') flag++;
else if (version == '12.4(15)T5') flag++;
else if (version == '12.4(15)T4') flag++;
else if (version == '12.4(15)T3') flag++;
else if (version == '12.4(15)T2') flag++;
else if (version == '12.4(15)T1') flag++;
else if (version == '12.4(15)T') flag++;
else if (version == '12.4(11)T4') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T7') flag++;
else if (version == '12.4(9)T6') flag++;
else if (version == '12.4(9)T5') flag++;
else if (version == '12.4(9)T4') flag++;
else if (version == '12.4(9)T3') flag++;
else if (version == '12.4(9)T2') flag++;
else if (version == '12.4(9)T1') flag++;
else if (version == '12.4(9)T') flag++;
else if (version == '12.4(19)MR') flag++;
else if (version == '12.4(16)MR2') flag++;
else if (version == '12.4(16)MR1') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_crypto_ctcp", "show crypto ctcp");
    if (check_cisco_result(buf))
    {
      flag = 1;
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
