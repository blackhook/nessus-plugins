#TRUSTED 611801e369fcbfedf3fd88989bdfda9da3d078b0ca2e4a422625903a52b098c1f099b510e5b76dc7dff47ba10d9a8393539fce3ebdd7e1ee25093c3f6b5c7baa93f7f2f3941e9400d1db0eccd2c6ec23a750fc0818cc95ca56ed628b6246d078db183637d34ca82c9865c6e650fd93de35d306b1958fb90a95355dab42bb258af185dac2d822c2fac3b40d45dc7d20adebca49962d223b2690f2688b3ba166f07e207868bef63738473471242f56c052179b466e599118ed310c04c8dce0b0c3b5be3fa2f03341eacf4c6b107d6a793135b976418d825f45f4aeda4af30a39f2dff9962f301cc12f8083799a826fd538eedabc9db14be91a4856195506e458c656597ab992aaf7c40cc2e70dca14c7210307770ac8db3a6aad99445c0abbc5b113694240b98ca5d457ff48ae12a73f6c0f3c1b11b63fc45460393c0a92ec20195c0eded3c0e732c1f00dd2bc920d131892235ee583e7c0b318b80c6e75003566b11bf1a58063930f54dd327f6bc493253a9c97447ab27110c3ab91d5a46619ed270b60ac10a948838bc8a44d4fe238aaf00c978b87b336f7db2edc6326c20e3198867e6c3354be0b7fe48bb781b95c55e38549d5e7ef7ef3a61f44b9c5eee4118b9cf982ce11650d51d2314d95f3b9890b2b876c8b1f06f7ad5dcaf7c702934c18b5b257f04b4e478ca79549add1d8438cab717a0e4fd6463e96fa3ba6a1caf3
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080af811c.shtml

include("compat.inc");

if (description)
{
 script_id(49047);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_cve_id("CVE-2009-2871");
 script_bugtraq_id(36493);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsq24002");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-tls");

 script_name(english:"Cisco IOS Software Crafted Encryption Packet Denial of Service Vulnerability - Cisco Systems");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Cisco IOS Software contains a vulnerability that could allow an
attacker to cause a Cisco IOS device to reload by remotely sending a
crafted encryption packet.

 Cisco has released free software updates that address this
vulnerability.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f233cf9");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080af811c.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acab276b");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-tls.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
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

if (version == '12.4(20)YA3') flag++;
else if (version == '12.4(20)YA2') flag++;
else if (version == '12.4(20)YA1') flag++;
else if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ2') flag++;
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
else if (version == '12.4(15)XR4') flag++;
else if (version == '12.4(15)XR3') flag++;
else if (version == '12.4(15)XR2') flag++;
else if (version == '12.4(15)XR1') flag++;
else if (version == '12.4(15)XR') flag++;
else if (version == '12.4(15)XQ2') flag++;
else if (version == '12.4(15)XQ1') flag++;
else if (version == '12.4(15)XQ') flag++;
else if (version == '12.4(14)XK') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(15)XF') flag++;
else if (version == '12.4(20)T2') flag++;
else if (version == '12.4(20)T1') flag++;
else if (version == '12.4(20)T') flag++;
else if (version == '12.4(15)T9') flag++;
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
else if (version == '12.4(15)SW3') flag++;
else if (version == '12.4(15)SW2') flag++;
else if (version == '12.4(15)SW1') flag++;
else if (version == '12.4(15)SW') flag++;
else if (version == '12.4(11)SW3') flag++;
else if (version == '12.4(11)SW2') flag++;
else if (version == '12.4(11)SW1') flag++;
else if (version == '12.4(11)SW') flag++;
else if (version == '12.4(19)MR2') flag++;
else if (version == '12.4(19)MR1') flag++;
else if (version == '12.4(19)MR') flag++;
else if (version == '12.4(16)MR2') flag++;
else if (version == '12.4(16)MR1') flag++;
else if (version == '12.4(16)MR') flag++;
else if (version == '12.4(12)MR2') flag++;
else if (version == '12.4(12)MR1') flag++;
else if (version == '12.4(12)MR') flag++;
else if (version == '12.4(11)MR') flag++;
else if (version == '12.4(15)MD2') flag++;
else if (version == '12.4(15)MD1') flag++;
else if (version == '12.4(15)MD') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"webvpn enable", multiline:TRUE, string:buf)) && (preg(pattern:"ssl trustpoint", multiline:TRUE, string:buf)) && (preg(pattern:"webvpn Gateway", multiline:TRUE, string:buf)) ) { flag = 1; }
      if (preg(pattern:"authentication rsa-encr", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ssh", "show ip ssh");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SSH Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
