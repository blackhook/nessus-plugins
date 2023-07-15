#TRUSTED 4eec157b8141222bfcf3346db2b281e68860efc19fab340f328c68dbf129faef44bd4b73622c9e2421363444557159a9711ef04ac4bb3184e55f08c3d95c3128c74cfec4d3a893eb0f32ff2c44e9761dd3bb8260ec5aa0e7faad462c675785a61a3d91e85f1c2cf3201eb4f27653d06f6010b8e38408e6fb2ec7cb55c5b3c0ed1e916c9c07264c92b85e4a0c9ebd04ff30c11bbf1bfe53a40c9e09fa09964ceaaa73356eeab3329bd95f3dc21890550fb5acebe905b14f7c2e5a99d3d0ebb679ecf0d0823b0a9e6365f5e2ef1eb416c16132e70e94d5cc533c218a63cd29f73cbc9a0b5d0c4570a49f9cd354da96daf15d82f3f5ad0497b8e216754284262347daa0258a05de44279146e60d2b2a9682c73f8ad5387ba6526ab6618425da3a4bb5319ff5721fa1f2d8a87c59acdd6895de762a16cd4727a7b177a78efe71ee310bc90122d0665a3f15ad2efd236bf15c320c8cba7de51200417bd290e5549ed25a91a1e069d9c62359b4e0ee2256b9d922c3efcc711648623235892e90b8bee5547c9cf9c784d05aa4296cec6f43ad569a4aba5310556607b8b4b03da66bf41d9894ede765265a32cae974d4407a0c9f6aa33bf1397b634a6522a378826a022f93dcf4852460a81b4d3669d266d24cbc90da9813ad3aa687cf024358bbbe3b3e1facc3dda6c3679aa36a21fc4cb3fa11fb15084ddcc6b567ff245802ce5d49bd
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080a0148e.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49024);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2008-3810", "CVE-2008-3811");
 script_bugtraq_id(31359);
 script_name(english:"Cisco IOS NAT Skinny Call Control Protocol Vulnerability");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'A series of segmented Skinny Call Control Protocol (SCCP) messages may
cause a Cisco IOS device that is configured with the Network Address
Translation (NAT) SCCP Fragmentation Support feature to reload.
 Cisco has released free software updates that address this
vulnerability. A workaround that mitigates this vulnerability is
available.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?feaa4924");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080a0148e.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?20ccd9c3");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-sccp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsg22426");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsi17020");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-sccp");
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

if (version == '12.4(11)XW6') flag++;
else if (version == '12.4(11)XW5') flag++;
else if (version == '12.4(11)XW4') flag++;
else if (version == '12.4(11)XW3') flag++;
else if (version == '12.4(11)XW2') flag++;
else if (version == '12.4(11)XW1') flag++;
else if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(6)XT2') flag++;
else if (version == '12.4(6)XT1') flag++;
else if (version == '12.4(6)XT') flag++;
else if (version == '12.4(6)XP') flag++;
else if (version == '12.4(15)XN') flag++;
else if (version == '12.4(15)XM') flag++;
else if (version == '12.4(15)XL1') flag++;
else if (version == '12.4(15)XL') flag++;
else if (version == '12.4(14)XK') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(9)XG4') flag++;
else if (version == '12.4(9)XG3') flag++;
else if (version == '12.4(9)XG2') flag++;
else if (version == '12.4(9)XG1') flag++;
else if (version == '12.4(9)XG') flag++;
else if (version == '12.4(15)XF') flag++;
else if (version == '12.4(6)XE3') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(4)XC7') flag++;
else if (version == '12.4(4)XC6') flag++;
else if (version == '12.4(4)XC5') flag++;
else if (version == '12.4(4)XC4') flag++;
else if (version == '12.4(4)XC3') flag++;
else if (version == '12.4(4)XC2') flag++;
else if (version == '12.4(4)XC1') flag++;
else if (version == '12.4(4)XC') flag++;
else if (version == '12.4(15)T1') flag++;
else if (version == '12.4(15)T') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T4') flag++;
else if (version == '12.4(9)T3') flag++;
else if (version == '12.4(9)T2') flag++;
else if (version == '12.4(9)T1') flag++;
else if (version == '12.4(9)T') flag++;
else if (version == '12.4(6)T9') flag++;
else if (version == '12.4(6)T8') flag++;
else if (version == '12.4(6)T7') flag++;
else if (version == '12.4(6)T6') flag++;
else if (version == '12.4(6)T5') flag++;
else if (version == '12.4(6)T4') flag++;
else if (version == '12.4(6)T3') flag++;
else if (version == '12.4(6)T2') flag++;
else if (version == '12.4(6)T10') flag++;
else if (version == '12.4(6)T1') flag++;
else if (version == '12.4(6)T') flag++;
else if (version == '12.4(15)SW1') flag++;
else if (version == '12.4(15)SW') flag++;
else if (version == '12.4(11)SW3') flag++;
else if (version == '12.4(11)SW2') flag++;
else if (version == '12.4(11)SW1') flag++;
else if (version == '12.4(11)SW') flag++;
else if (version == '12.4(12)MR2') flag++;
else if (version == '12.4(12)MR1') flag++;
else if (version == '12.4(12)MR') flag++;
else if (version == '12.4(11)MR') flag++;
else if (version == '12.4(9)MR') flag++;
else if (version == '12.4(6)MR1') flag++;
else if (version == '12.4(6)MR') flag++;
else if (version == '12.4(11)MD3') flag++;
else if (version == '12.4(11)MD2') flag++;
else if (version == '12.4(11)MD1') flag++;
else if (version == '12.4(11)MD') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"\s+ip\s+nat\s+inside", multiline:TRUE, string:buf)) && (preg(pattern:"\s+ip\s+nat\s+outside", multiline:TRUE, string:buf)) ) { flag = 1; }
      if (preg(pattern:"\s+ip\s+nat\s+enable", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
