#TRUSTED 9ce32707e9bce2e33a215415fa5b6a3c9a93666cf5e9a77193a9988e9c71d0c234d57f452a344abfa734717909e0650124b7654332f32adc7cf44ffaecfa03d123e9747bc518337fee27d214214022005090a74753880514dff53dd8d805a0ddaab2503dde6d9d0c5e3f1d249e5a1016b136f3d477edfaf49a12041a846849706ca9a69b4b6bbbe04138300abfa1a2034e7e7f125280480a846b744d6f7dc965c01fac72b2482bc35644048572debf677134ef97f8cdb401102dc828d9863d9cc190e8b72044dec15806d8be6847bfd83809465602f198ce7f60dc8bb273114786c9f2a5437f9c2881450afed3485fd528c274a987221f2beb2b16c77b4e79e94effcf41544de6d7e8d39b36830fe4c631e3d1f327e469a63f799cc9072a06624c931ef274c2f9dd33fdeb8df931580e0ea46fe1a801151f92ae105d2956e37e08bfb67a54950a7b1c59ea957fc9f115a1042aeaa1489bae7890c63a8fb2c9eff5f2ec82e56d021a9261e9d897cd8440a4ebd2dcb375865246592da3f652b6900c918c931bea840da75b88c1af2b092584d15073d83f666b58ff95e2a3852eaf9a36225b4ef36984288d1ca68d11a7a8483463a37c5e15c4b5f953f800537f5960713f5efaa576aad26a8b5f9d96e48934e443c63cc46c1dedaf44c19364ed6b7b7212a8754bd79df7dcdeb91e8ac0ad1284c56ece25ffd0ec6dcfedf3a39bc9
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080af8117.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49044);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2009-2868");
 script_bugtraq_id(36497);
 script_xref(name:"CISCO-BUG-ID", value:"CSCee72997");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsy07555");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-ipsec");
 script_name(english:"Cisco IOS Software Internet Key Exchange Resource Exhaustion Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco IOS devices that are configured for Internet Key Exchange (IKE)
protocol and certificate based authentication are vulnerable to a
resource exhaustion attack. Successful exploitation of this
vulnerability may result in the allocation of all available Phase 1
security associations (SA) and prevent the establishment of new IPsec
sessions.
 Cisco has released free software updates that address this
vulnerability.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ab223fe");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080af8117.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?18367fb5");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-ipsec.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
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

if (version == '12.4(4)XD9') flag++;
else if (version == '12.4(4)XD8') flag++;
else if (version == '12.4(4)XD7') flag++;
else if (version == '12.4(4)XD5') flag++;
else if (version == '12.4(4)XD4') flag++;
else if (version == '12.4(4)XD2') flag++;
else if (version == '12.4(4)XD12') flag++;
else if (version == '12.4(4)XD11') flag++;
else if (version == '12.4(4)XD10') flag++;
else if (version == '12.4(4)XD1') flag++;
else if (version == '12.4(4)XD') flag++;
else if (version == '12.4(4)XC7') flag++;
else if (version == '12.4(4)XC6') flag++;
else if (version == '12.4(4)XC5') flag++;
else if (version == '12.4(4)XC4') flag++;
else if (version == '12.4(4)XC3') flag++;
else if (version == '12.4(4)XC2') flag++;
else if (version == '12.4(4)XC1') flag++;
else if (version == '12.4(4)XC') flag++;
else if (version == '12.4(2)XB9') flag++;
else if (version == '12.4(2)XB8') flag++;
else if (version == '12.4(2)XB7') flag++;
else if (version == '12.4(2)XB6') flag++;
else if (version == '12.4(2)XB5') flag++;
else if (version == '12.4(2)XB4') flag++;
else if (version == '12.4(2)XB3') flag++;
else if (version == '12.4(2)XB2') flag++;
else if (version == '12.4(2)XB10') flag++;
else if (version == '12.4(2)XB1') flag++;
else if (version == '12.4(2)XB') flag++;
else if (version == '12.4(2)XA2') flag++;
else if (version == '12.4(2)XA1') flag++;
else if (version == '12.4(2)XA') flag++;
else if (version == '12.4(6)T') flag++;
else if (version == '12.4(4)T7') flag++;
else if (version == '12.4(4)T6') flag++;
else if (version == '12.4(4)T5') flag++;
else if (version == '12.4(4)T4') flag++;
else if (version == '12.4(4)T3') flag++;
else if (version == '12.4(4)T2') flag++;
else if (version == '12.4(4)T1') flag++;
else if (version == '12.4(4)T') flag++;
else if (version == '12.4(2)T6') flag++;
else if (version == '12.4(2)T5') flag++;
else if (version == '12.4(2)T4') flag++;
else if (version == '12.4(2)T3') flag++;
else if (version == '12.4(2)T2') flag++;
else if (version == '12.4(2)T1') flag++;
else if (version == '12.4(2)T') flag++;
else if (version == '12.4(7)') flag++;
else if (version == '12.4(5a)') flag++;
else if (version == '12.4(5)') flag++;
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
else if (version == '12.3(11)YZ2') flag++;
else if (version == '12.3(11)YZ1') flag++;
else if (version == '12.3(11)YZ') flag++;
else if (version == '12.3(14)YX9') flag++;
else if (version == '12.3(14)YX8') flag++;
else if (version == '12.3(14)YX7') flag++;
else if (version == '12.3(14)YX4') flag++;
else if (version == '12.3(14)YX3') flag++;
else if (version == '12.3(14)YX2') flag++;
else if (version == '12.3(14)YX15') flag++;
else if (version == '12.3(14)YX14') flag++;
else if (version == '12.3(14)YX13') flag++;
else if (version == '12.3(14)YX12') flag++;
else if (version == '12.3(14)YX11') flag++;
else if (version == '12.3(14)YX10') flag++;
else if (version == '12.3(14)YX1') flag++;
else if (version == '12.3(14)YX') flag++;
else if (version == '12.3(14)YU1') flag++;
else if (version == '12.3(14)YU') flag++;
else if (version == '12.3(14)YT1') flag++;
else if (version == '12.3(14)YT') flag++;
else if (version == '12.3(11)YS2') flag++;
else if (version == '12.3(11)YS1') flag++;
else if (version == '12.3(11)YS') flag++;
else if (version == '12.3(14)YQ8') flag++;
else if (version == '12.3(14)YQ7') flag++;
else if (version == '12.3(14)YQ6') flag++;
else if (version == '12.3(14)YQ5') flag++;
else if (version == '12.3(14)YQ4') flag++;
else if (version == '12.3(14)YQ3') flag++;
else if (version == '12.3(14)YQ2') flag++;
else if (version == '12.3(14)YQ1') flag++;
else if (version == '12.3(14)YQ') flag++;
else if (version == '12.3(11)YK3') flag++;
else if (version == '12.3(11)YK2') flag++;
else if (version == '12.3(11)YK1') flag++;
else if (version == '12.3(11)YK') flag++;
else if (version == '12.3(8)YI3') flag++;
else if (version == '12.3(8)YI2') flag++;
else if (version == '12.3(8)YI1') flag++;
else if (version == '12.3(8)YH') flag++;
else if (version == '12.3(8)YG6') flag++;
else if (version == '12.3(8)YG5') flag++;
else if (version == '12.3(8)YG4') flag++;
else if (version == '12.3(8)YG3') flag++;
else if (version == '12.3(8)YG2') flag++;
else if (version == '12.3(8)YG1') flag++;
else if (version == '12.3(8)YG') flag++;
else if (version == '12.3(11)YF4') flag++;
else if (version == '12.3(11)YF3') flag++;
else if (version == '12.3(11)YF2') flag++;
else if (version == '12.3(11)YF1') flag++;
else if (version == '12.3(11)YF') flag++;
else if (version == '12.3(8)YD1') flag++;
else if (version == '12.3(8)YD') flag++;
else if (version == '12.3(8)YA1') flag++;
else if (version == '12.3(8)YA') flag++;
else if (version == '12.3(8)XX2d') flag++;
else if (version == '12.3(8)XX1') flag++;
else if (version == '12.3(8)XX') flag++;
else if (version == '12.3(7)XS2') flag++;
else if (version == '12.3(7)XS1') flag++;
else if (version == '12.3(7)XS') flag++;
else if (version == '12.3(7)XR7') flag++;
else if (version == '12.3(7)XR6') flag++;
else if (version == '12.3(7)XR5') flag++;
else if (version == '12.3(7)XR4') flag++;
else if (version == '12.3(7)XR3') flag++;
else if (version == '12.3(7)XR2') flag++;
else if (version == '12.3(7)XR') flag++;
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
else if (version == '12.2(2)XU1') flag++;
else if (version == '12.2(2)XT1') flag++;
else if (version == '12.2(1)XS1') flag++;
else if (version == '12.2(33)XN1') flag++;
else if (version == '12.2(33)SXI1') flag++;
else if (version == '12.2(33)SXI') flag++;
else if (version == '12.2(33)SXH5') flag++;
else if (version == '12.2(33)SXH4') flag++;
else if (version == '12.2(33)SXH3a') flag++;
else if (version == '12.2(33)SXH3') flag++;
else if (version == '12.2(33)SXH2a') flag++;
else if (version == '12.2(33)SXH2') flag++;
else if (version == '12.2(33)SXH1') flag++;
else if (version == '12.2(33)SXH') flag++;
else if (version == '12.2(25)SW') flag++;
else if (version == '12.2(33)SRD2') flag++;
else if (version == '12.2(33)SRD1') flag++;
else if (version == '12.2(33)SRD') flag++;
else if (version == '12.2(33)SRC4') flag++;
else if (version == '12.2(33)SRC3') flag++;
else if (version == '12.2(33)SRC2') flag++;
else if (version == '12.2(33)SRC1') flag++;
else if (version == '12.2(33)SRC') flag++;
else if (version == '12.2(33)SRB5a') flag++;
else if (version == '12.2(33)SRB5') flag++;
else if (version == '12.2(33)SRB4') flag++;
else if (version == '12.2(33)SRB3') flag++;
else if (version == '12.2(33)SRB2') flag++;
else if (version == '12.2(33)SRB1') flag++;
else if (version == '12.2(33)SRB') flag++;
else if (version == '12.2(33)SRA7') flag++;
else if (version == '12.2(33)SRA6') flag++;
else if (version == '12.2(33)SRA5') flag++;
else if (version == '12.2(33)SRA4') flag++;
else if (version == '12.2(33)SRA3') flag++;
else if (version == '12.2(33)SRA2') flag++;
else if (version == '12.2(33)SRA1') flag++;
else if (version == '12.2(33)SRA') flag++;
else if (version == '12.2(50)SE1') flag++;
else if (version == '12.2(50)SE') flag++;
else if (version == '12.2(46)SE') flag++;
else if (version == '12.2(44)SE6') flag++;
else if (version == '12.2(44)SE5') flag++;
else if (version == '12.2(44)SE3') flag++;
else if (version == '12.2(44)SE2') flag++;
else if (version == '12.2(44)SE1') flag++;
else if (version == '12.2(44)SE') flag++;
else if (version == '12.2(40)SE') flag++;
else if (version == '12.2(33)SCB3') flag++;
else if (version == '12.2(33)SCB2') flag++;
else if (version == '12.2(33)SCB1') flag++;
else if (version == '12.2(33)SCB') flag++;
else if (version == '12.2(33)SCA2') flag++;
else if (version == '12.2(33)SCA1') flag++;
else if (version == '12.2(33)SCA') flag++;
else if (version == '12.2(33)SB4') flag++;
else if (version == '12.2(33)SB3') flag++;
else if (version == '12.2(33)SB2') flag++;
else if (version == '12.2(33)SB1') flag++;
else if (version == '12.2(33)SB') flag++;
else if (version == '12.2(33)IRC') flag++;
else if (version == '12.2(33)IRB') flag++;
else if (version == '12.2(33)IRA') flag++;


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_crypto_key_mypubkey_rsa", "show crypto key mypubkey rsa");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Key Data:", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\s500\s", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"\s4500\s", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"\s848\s", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"\s4848\s", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_crypto_isakmp_policy", "show crypto isakmp policy");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Rivest-Shamir-Adleman Signature", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
