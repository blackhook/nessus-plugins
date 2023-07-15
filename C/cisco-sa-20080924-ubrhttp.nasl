#TRUSTED 6ff02c9e9f6fa4f6a1d9d4739c62d2005041e3ffa63b2461b9aafa210de949d520628e80e007af94a7e7c310309c3dc0645abef5f9b877312a2f5aabc5727a3ba8c76b1541654d9e58947582d807de5ae9c1f1b76aba4988ddaefa65c0b35b646ecdae4dd7a7ab230a2fb5b183b56e7af48311974e543eb0cabbcab3a648e06d742283845e9facbb7622643afecf82c359bc7e8850ab48db15dd2482ad7a0589739d8216f0d52605ed11090f684e6dd6c3376d91cdb02ac52f453614450517c5c3b72754626bd2975dfc8cf5bc609d9ec0e4462d80d53738764bd657ee92bcdec46692e39e13c5b11e588e91b03ef0a2273c56b3b45efa09d3ed08fe46f1c99c6a5832bb342ccc506af65a9221020f1dd0301a716e5ee1f1e9ec9f2d5603d1c95ed4b91308774730a5e61d8eb78925764b10e9d8107db947c8464f54e3300cfbf2fa28afd926f6318ab0661497033176483f2675376607b2002c12000e57fe32e2c73929e6139ea81f4df83bfa1b74e066e7fcdbbbaf88a620eeb6d4f2797c6ad085a37b076a6fe50c4a7657d3d4b2e809e3a6859f3cbeeb160903966c787cf3384ebd6ed6d8d5cd63d4735f354c7dc0bd89335b09e5ad89b212ab8d5cf7b1063b500f47381bb55069379f81d0e53aafea6332466162ee0c3a584a8ab642db5e34e7ab9c00d7d5ed678b829be7061fd920150fa38ac4f6171393751eee8f015c
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080a014b1.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49027);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2019/09/26");
 script_cve_id("CVE-2008-3807");
 script_bugtraq_id(31355);
 script_xref(name:"CISCO-BUG-ID", value:"CSCek57932");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-ubr");
 script_name(english:"Cisco uBR10012 Series Devices SNMP Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco uBR10012 series devices automatically enable Simple Network
Management Protocol (SNMP) read/write access to the device if
configured for linecard redundancy. This can be exploited by an
attacker to gain complete control of the device. Only Cisco uBR10012
series devices that are configured for linecard redundancy are
affected.

 Cisco has released free software updates that address this
vulnerability. Workarounds that mitigate this vulnerability are
available.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24d1a74f");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080a014b1.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?7c05ab7f");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-ubr.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(16);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2019 Tenable Network Security, Inc.");
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

if (version == '12.3(17b)BC7') flag++;
else if (version == '12.3(17b)BC6') flag++;
else if (version == '12.3(17b)BC5') flag++;
else if (version == '12.3(17b)BC4') flag++;
else if (version == '12.3(17b)BC3') flag++;
else if (version == '12.3(17a)BC2') flag++;
else if (version == '12.3(17a)BC1') flag++;
else if (version == '12.3(17a)BC') flag++;
else if (version == '12.3(13a)BC6') flag++;
else if (version == '12.3(13a)BC5') flag++;
else if (version == '12.3(13a)BC4') flag++;
else if (version == '12.3(13a)BC3') flag++;
else if (version == '12.3(13a)BC2') flag++;
else if (version == '12.3(13a)BC1') flag++;
else if (version == '12.3(13a)BC') flag++;
else if (version == '12.3(9a)BC9') flag++;
else if (version == '12.3(9a)BC8') flag++;
else if (version == '12.3(9a)BC7') flag++;
else if (version == '12.3(9a)BC6') flag++;
else if (version == '12.3(9a)BC5') flag++;
else if (version == '12.3(9a)BC4') flag++;
else if (version == '12.3(9a)BC3') flag++;
else if (version == '12.3(9a)BC2') flag++;
else if (version == '12.3(9a)BC1') flag++;
else if (version == '12.3(9a)BC') flag++;
else if (version == '12.2(4)XF1') flag++;
else if (version == '12.2(4)XF') flag++;
else if (version == '12.2(11)CY') flag++;
else if (version == '12.2(15)CX1') flag++;
else if (version == '12.2(15)CX') flag++;
else if (version == '12.2(11)CX') flag++;
else if (version == '12.2(15)BC2i') flag++;
else if (version == '12.2(15)BC2h') flag++;
else if (version == '12.2(15)BC2g') flag++;
else if (version == '12.2(15)BC2f') flag++;
else if (version == '12.2(15)BC2e') flag++;
else if (version == '12.2(15)BC2d') flag++;
else if (version == '12.2(15)BC2c') flag++;
else if (version == '12.2(15)BC2b') flag++;
else if (version == '12.2(15)BC2a') flag++;
else if (version == '12.2(15)BC2') flag++;
else if (version == '12.2(15)BC1g') flag++;
else if (version == '12.2(15)BC1f') flag++;
else if (version == '12.2(15)BC1e') flag++;
else if (version == '12.2(15)BC1d') flag++;
else if (version == '12.2(15)BC1c') flag++;
else if (version == '12.2(15)BC1b') flag++;
else if (version == '12.2(15)BC1a') flag++;
else if (version == '12.2(15)BC1') flag++;
else if (version == '12.2(11)BC3d') flag++;
else if (version == '12.2(11)BC3c') flag++;
else if (version == '12.2(11)BC3b') flag++;
else if (version == '12.2(11)BC3a') flag++;
else if (version == '12.2(11)BC3') flag++;
else if (version == '12.2(11)BC2a') flag++;
else if (version == '12.2(11)BC2') flag++;
else if (version == '12.2(11)BC1b') flag++;
else if (version == '12.2(11)BC1a') flag++;
else if (version == '12.2(11)BC1') flag++;
else if (version == '12.2(8)BC2a') flag++;
else if (version == '12.2(8)BC2') flag++;
else if (version == '12.2(8)BC1') flag++;
else if (version == '12.2(4)BC1b') flag++;
else if (version == '12.2(4)BC1a') flag++;
else if (version == '12.2(4)BC1') flag++;


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"member subslot [^\r\n]+ working", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"hccp [^\r\n]+ protect ", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
