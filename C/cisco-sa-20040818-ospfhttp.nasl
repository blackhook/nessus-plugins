#TRUSTED 7823caadd19021afe931a8bcd67764793579957e5d3c7ed3a232c0abc95afe38c7981f921c1571c8f5b44f36b385d581c4362ddaf24cfa96e792f5019a4bbd39f683cd095277a5cee4a6ed082c6aafce447a22ec0ce492e91f348555dc363e0a1458ef7d956c5dce6d15b62c2bac9a57930bfcb8858d7182af76c03354eba95e0ce3f12738f0d1d2b7569b2fe41f0a26e281060cf25f08975d10536b5a9f8a63a68a25098acc46eb2b367f18d567dec77b318574da345b97ea2ff2456956ea1892d9ba53b4740aaf0e71d8fd064a4eddc76e42a72ff91a0a650e0bc2319e4c01512762474e7ae7d292d4ac9f414775bd30a1d98efc68d97cfce1778af8946cb5b386d9c1a1d08b527ca55a1d33614cbcf8405149fd22ff6c3e1195006018d521af4aefe9e2afb71ff9561abcc2d12ca43500f5eebe61d1b81f9987639e5ebfbc152eab86949f2b191923613d413f73e9765ca5c38645425a7c3ccad3a87a2c6c4b63675e2da7cd7eb6534f98bafcc8b460c13463f193bf3d61fd2b9954ae1df44697ac9b79013eab219d0e5cd838a5a89a131d97f5266b4e6cec657a7785120b7da7496b0de5f67b21973dc7a94028c14e3d9660f731c2b0766d5da672d8e5933f262316727bda8846ab1e6381fb4e466e6a59a4eba15d35711cf4178b86106c72a2e1b29ccd7569178f4829c8f713e1507cd220459a862dc29f5aeb170bf2ad
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a008029e189.shtml

include("compat.inc");

if (description)
{
 script_id(48976);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_cve_id("CVE-2004-1454");
 script_xref(name:"CISCO-BUG-ID", value:"CSCec16481");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20040818-ospf");

 script_name(english:"Cisco IOS Malformed OSPF Packet Causes Reload - Cisco Systems");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"A Cisco device running Internetwork Operating System (IOS) and
enabled for the Open Shortest Path First (OSPF) protocol is vulnerable
to a denial of service (DoS) attack from a malformed OSPF packet. The
OSPF protocol is not enabled by default.

The vulnerability is only present in Cisco IOS release trains based on
12.0S, 12.2, and 12.3. Releases based on 12.0, 12.1 mainlines, and all
Cisco IOS images prior to 12.0 are not affected.

Cisco has made free software available to address this vulnerability.
There are workarounds available to mitigate the effects.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ff05ae1");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a008029e189.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0bb2a4e");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20040818-ospf.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/08/18");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.3(2)XE') flag++;
else if (version == '12.3(2)XC2') flag++;
else if (version == '12.3(2)XC1') flag++;
else if (version == '12.3(2)XC') flag++;
else if (version == '12.3(2)XB1') flag++;
else if (version == '12.3(2)XB') flag++;
else if (version == '12.3(2)XA4') flag++;
else if (version == '12.3(2)XA2') flag++;
else if (version == '12.3(2)XA1') flag++;
else if (version == '12.3(2)XA') flag++;
else if (version == '12.3(2)T3') flag++;
else if (version == '12.3(2)T2') flag++;
else if (version == '12.3(2)T1') flag++;
else if (version == '12.3(2)T') flag++;
else if (version == '12.3(1a)BW') flag++;
else if (version == '12.3(3)B1') flag++;
else if (version == '12.3(3)B') flag++;
else if (version == '12.3(1a)B') flag++;
else if (version == '12.3(3e)') flag++;
else if (version == '12.3(3c)') flag++;
else if (version == '12.3(3b)') flag++;
else if (version == '12.3(3a)') flag++;
else if (version == '12.3(3)') flag++;
else if (version == '12.3(1a)') flag++;
else if (version == '12.3(1)') flag++;
else if (version == '12.2(15)ZL1') flag++;
else if (version == '12.2(15)ZL') flag++;
else if (version == '12.2(15)ZJ5') flag++;
else if (version == '12.2(15)ZJ3') flag++;
else if (version == '12.2(15)ZJ2') flag++;
else if (version == '12.2(15)ZJ1') flag++;
else if (version == '12.2(15)ZJ') flag++;
else if (version == '12.2(13)ZH5') flag++;
else if (version == '12.2(13)ZH3') flag++;
else if (version == '12.2(13)ZH2') flag++;
else if (version == '12.2(13)ZH') flag++;
else if (version == '12.2(13)ZF2') flag++;
else if (version == '12.2(13)ZF1') flag++;
else if (version == '12.2(13)ZF') flag++;
else if (version == '12.2(13)ZE') flag++;
else if (version == '12.2(13)ZD4') flag++;
else if (version == '12.2(13)ZD3') flag++;
else if (version == '12.2(13)ZD2') flag++;
else if (version == '12.2(13)ZD1') flag++;
else if (version == '12.2(13)ZD') flag++;
else if (version == '12.2(11)YV') flag++;
else if (version == '12.2(11)YU') flag++;
else if (version == '12.2(15)T7') flag++;
else if (version == '12.2(15)T5') flag++;
else if (version == '12.2(15)T4e') flag++;
else if (version == '12.2(15)T4') flag++;
else if (version == '12.2(15)T2') flag++;
else if (version == '12.2(15)T1') flag++;
else if (version == '12.2(15)T') flag++;
else if (version == '12.2(14)SZ6') flag++;
else if (version == '12.2(14)SZ5') flag++;
else if (version == '12.2(14)SZ4') flag++;
else if (version == '12.2(14)SZ3') flag++;
else if (version == '12.2(14)SZ2') flag++;
else if (version == '12.2(14)SZ1') flag++;
else if (version == '12.2(14)SZ') flag++;
else if (version == '12.2(19)SW') flag++;
else if (version == '12.2(18)SW') flag++;
else if (version == '12.2(18)SV3') flag++;
else if (version == '12.2(18)SV2') flag++;
else if (version == '12.2(18)SV1') flag++;
else if (version == '12.2(18)SV') flag++;
else if (version == '12.2(18)SE1') flag++;
else if (version == '12.2(18)SE') flag++;
else if (version == '12.2(18)S4') flag++;
else if (version == '12.2(18)S3') flag++;
else if (version == '12.2(18)S2') flag++;
else if (version == '12.2(18)S1') flag++;
else if (version == '12.2(18)S') flag++;
else if (version == '12.2(15)MC2') flag++;
else if (version == '12.2(15)MC1c') flag++;
else if (version == '12.2(15)MC1b') flag++;
else if (version == '12.2(15)MC1a') flag++;
else if (version == '12.2(15)MC1') flag++;
else if (version == '12.2(18)EW') flag++;
else if (version == '12.2(15)CX1') flag++;
else if (version == '12.2(15)CX') flag++;
else if (version == '12.2(15)BZ2') flag++;
else if (version == '12.2(16)BX3') flag++;
else if (version == '12.2(16)BX2') flag++;
else if (version == '12.2(16)BX1') flag++;
else if (version == '12.2(16)BX') flag++;
else if (version == '12.2(15)BX') flag++;
else if (version == '12.2(15)BC1b') flag++;
else if (version == '12.2(15)BC1a') flag++;
else if (version == '12.2(15)BC1') flag++;
else if (version == '12.2(16)B2') flag++;
else if (version == '12.2(16)B1') flag++;
else if (version == '12.2(16)B') flag++;
else if (version == '12.2(15)B') flag++;
else if (version == '12.0(23)SZ3') flag++;
else if (version == '12.0(25)SX1') flag++;
else if (version == '12.0(25)SX') flag++;
else if (version == '12.0(23)SX5') flag++;
else if (version == '12.0(23)SX4') flag++;
else if (version == '12.0(23)SX3') flag++;
else if (version == '12.0(23)SX2') flag++;
else if (version == '12.0(23)SX1') flag++;
else if (version == '12.0(23)SX') flag++;
else if (version == '12.0(26)S') flag++;
else if (version == '12.0(25)S1c') flag++;
else if (version == '12.0(25)S1b') flag++;
else if (version == '12.0(25)S1a') flag++;
else if (version == '12.0(25)S1') flag++;
else if (version == '12.0(25)S') flag++;
else if (version == '12.0(24)S3') flag++;
else if (version == '12.0(24)S2b') flag++;
else if (version == '12.0(24)S2a') flag++;
else if (version == '12.0(24)S2') flag++;
else if (version == '12.0(24)S1') flag++;
else if (version == '12.0(24)S') flag++;
else if (version == '12.0(23)S4') flag++;
else if (version == '12.0(23)S3c') flag++;
else if (version == '12.0(23)S3b') flag++;
else if (version == '12.0(23)S3a') flag++;
else if (version == '12.0(23)S3') flag++;
else if (version == '12.0(23)S2a') flag++;
else if (version == '12.0(23)S2') flag++;
else if (version == '12.0(23)S1') flag++;
else if (version == '12.0(23)S') flag++;
else if (version == '12.0(22)S5a') flag++;
else if (version == '12.0(22)S5') flag++;
else if (version == '12.0(22)S4a') flag++;
else if (version == '12.0(22)S4') flag++;
else if (version == '12.0(22)S3c') flag++;
else if (version == '12.0(22)S3b') flag++;
else if (version == '12.0(22)S3a') flag++;
else if (version == '12.0(22)S3') flag++;
else if (version == '12.0(22)S2e') flag++;
else if (version == '12.0(22)S2d') flag++;
else if (version == '12.0(22)S2c') flag++;
else if (version == '12.0(22)S2b') flag++;
else if (version == '12.0(22)S2a') flag++;
else if (version == '12.0(22)S2') flag++;
else if (version == '12.0(22)S1') flag++;
else if (version == '12.0(22)S') flag++;



if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"router\s+ospf\s+", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
