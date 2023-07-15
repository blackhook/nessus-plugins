#TRUSTED 8a5a2cad42be9d305af07e79517c3e563dda7ec210c2d9bf110de3a7f74c39c8bcb0aa7aa0b145534e90895b8ed8c5d322b3a9cf220a5bb3bea0891771156d1c2a00c3c24ae799c94527dfefec824dcbacc130ad07d4882f13bc2c10cfd95f612b59ab02231487cdb2d3b8454dcf3aa9f25527dc7f7b34b766254a7fe757746562fbdbcbebcd04b7acd0aa085fbde16bdae4030a48d2ff885ede101172e911ceb397c69118483ae85058a6e44f19ce6eae39bf442e8c00bb6def3270b406479e2bb1a76aab196db2f123e1f73ba4c41bb8a644cce677c35a97afc4768db5833789efc6dafab349cbdc8997058e33b39bb95bcd8c6efe123396af1285a8681b0eed599c946e64338bcd49414ac97c60ced54dab300e715a203b8114c762b2370a9f88a302013d99af4403e8f202cdb27a2b67d8ff24aac5d12294587929f5a15150d714f9fbd50cad63f6910c669e24fe38ecd4f14156ef77e19ed283b7dd7ab4b0467cb46f1b8d469e5f3623a069f4f15275103d27cc2c8e902bf126c0b7cb270fcbe8ca3084746fcdca170130a12fe653bf35956d4a8892efdb85631f81af9c893e0ec29df80bce3a71aa651116af3a10fc71c6d2878e4d6119a15d0ec1116252ceaabec28ddd89ec7ba24bd815944bae2ab76ba637f307fceff1fe48a34b1c801e25c76fe5329b828f7e0d486ea5b0302f4a13d8c71b145ad91bf6679cf13c
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00803b3fff.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48979);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2005-0186");
 script_bugtraq_id(12307);
 script_name(english:"Vulnerability in Cisco IOS Embedded Call Processing Solutions - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco Internetwork Operating System (IOS) Software release trains
12.1YD, 12.2T, 12.3 and 12.3T, when configured for the Cisco IOS
Telephony Service (ITS), Cisco CallManager Express (CME) or Survivable
Remote Site Telephony (SRST) may contain a vulnerability in processing
certain malformed control protocol messages.'
 );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ca1d056");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00803b3fff.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?0e41b5df");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20050119-itscme.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/01/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCee08584");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20050119-itscme");
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

if (version == '12.3(2)XZ2') flag++;
else if (version == '12.3(2)XZ1') flag++;
else if (version == '12.3(2)XZ') flag++;
else if (version == '12.3(4)XQ') flag++;
else if (version == '12.3(4)XK') flag++;
else if (version == '12.3(7)XJ1') flag++;
else if (version == '12.3(7)XJ') flag++;
else if (version == '12.3(4)XG1') flag++;
else if (version == '12.3(4)XG') flag++;
else if (version == '12.3(2)XF') flag++;
else if (version == '12.3(2)XE') flag++;
else if (version == '12.3(4)XD4') flag++;
else if (version == '12.3(4)XD3') flag++;
else if (version == '12.3(4)XD2') flag++;
else if (version == '12.3(4)XD1') flag++;
else if (version == '12.3(4)XD') flag++;
else if (version == '12.3(2)XC2') flag++;
else if (version == '12.3(2)XC') flag++;
else if (version == '12.3(2)XB3') flag++;
else if (version == '12.3(2)XB1') flag++;
else if (version == '12.3(2)XB') flag++;
else if (version == '12.3(2)XA4') flag++;
else if (version == '12.3(2)XA1') flag++;
else if (version == '12.3(2)XA') flag++;
else if (version == '12.3(7)T') flag++;
else if (version == '12.3(4)T4') flag++;
else if (version == '12.3(4)T3') flag++;
else if (version == '12.3(4)T2a') flag++;
else if (version == '12.3(4)T2') flag++;
else if (version == '12.3(4)T1') flag++;
else if (version == '12.3(4)T') flag++;
else if (version == '12.3(2)T6') flag++;
else if (version == '12.3(2)T5') flag++;
else if (version == '12.3(2)T4') flag++;
else if (version == '12.3(2)T3') flag++;
else if (version == '12.3(2)T2') flag++;
else if (version == '12.3(2)T1') flag++;
else if (version == '12.3(2)T') flag++;
else if (version == '12.3(5a)B5') flag++;
else if (version == '12.3(5a)B4') flag++;
else if (version == '12.3(5a)B3') flag++;
else if (version == '12.3(5a)B2') flag++;
else if (version == '12.3(5a)B1') flag++;
else if (version == '12.3(5a)B') flag++;
else if (version == '12.3(3)B1') flag++;
else if (version == '12.3(3)B') flag++;
else if (version == '12.3(1a)B') flag++;
else if (version == '12.3(6b)') flag++;
else if (version == '12.3(6a)') flag++;
else if (version == '12.3(6)') flag++;
else if (version == '12.3(5c)') flag++;
else if (version == '12.3(5b)') flag++;
else if (version == '12.3(5a)') flag++;
else if (version == '12.3(5)') flag++;
else if (version == '12.3(3g)') flag++;
else if (version == '12.3(3f)') flag++;
else if (version == '12.3(3e)') flag++;
else if (version == '12.3(3c)') flag++;
else if (version == '12.3(3b)') flag++;
else if (version == '12.3(3a)') flag++;
else if (version == '12.3(3)') flag++;
else if (version == '12.3(1a)') flag++;
else if (version == '12.3(1)') flag++;
else if (version == '12.2(13)ZP4') flag++;
else if (version == '12.2(13)ZP3') flag++;
else if (version == '12.2(13)ZP2') flag++;
else if (version == '12.2(13)ZP1') flag++;
else if (version == '12.2(13)ZP') flag++;
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
else if (version == '12.2(13)ZC') flag++;
else if (version == '12.2(8)ZB8') flag++;
else if (version == '12.2(8)ZB7') flag++;
else if (version == '12.2(8)ZB6') flag++;
else if (version == '12.2(8)ZB5') flag++;
else if (version == '12.2(8)ZB4a') flag++;
else if (version == '12.2(8)ZB4') flag++;
else if (version == '12.2(8)ZB3') flag++;
else if (version == '12.2(8)ZB2') flag++;
else if (version == '12.2(8)ZB1') flag++;
else if (version == '12.2(8)YY4') flag++;
else if (version == '12.2(8)YY3') flag++;
else if (version == '12.2(8)YY2') flag++;
else if (version == '12.2(8)YY1') flag++;
else if (version == '12.2(8)YY') flag++;
else if (version == '12.2(8)YW3') flag++;
else if (version == '12.2(8)YW2') flag++;
else if (version == '12.2(8)YW1') flag++;
else if (version == '12.2(8)YW') flag++;
else if (version == '12.2(11)YV') flag++;
else if (version == '12.2(11)YU') flag++;
else if (version == '12.2(11)YT2') flag++;
else if (version == '12.2(11)YT1') flag++;
else if (version == '12.2(11)YT') flag++;
else if (version == '12.2(8)YN1') flag++;
else if (version == '12.2(8)YN') flag++;
else if (version == '12.2(8)YM') flag++;
else if (version == '12.2(8)YL') flag++;
else if (version == '12.2(8)YJ') flag++;
else if (version == '12.2(4)YH') flag++;
else if (version == '12.2(8)YD3') flag++;
else if (version == '12.2(8)YD2') flag++;
else if (version == '12.2(8)YD1') flag++;
else if (version == '12.2(8)YD') flag++;
else if (version == '12.2(2)YC4') flag++;
else if (version == '12.2(2)YC3') flag++;
else if (version == '12.2(2)YC2') flag++;
else if (version == '12.2(2)YC1') flag++;
else if (version == '12.2(2)YC') flag++;
else if (version == '12.2(4)YB') flag++;
else if (version == '12.2(4)YA7') flag++;
else if (version == '12.2(4)YA6') flag++;
else if (version == '12.2(4)YA2') flag++;
else if (version == '12.2(4)YA1') flag++;
else if (version == '12.2(4)YA') flag++;
else if (version == '12.2(4)XW') flag++;
else if (version == '12.2(2)XU') flag++;
else if (version == '12.2(2)XT3') flag++;
else if (version == '12.2(2)XT2') flag++;
else if (version == '12.2(2)XT') flag++;
else if (version == '12.2(4)XM4') flag++;
else if (version == '12.2(4)XM3') flag++;
else if (version == '12.2(4)XM2') flag++;
else if (version == '12.2(4)XM') flag++;
else if (version == '12.2(2)XG') flag++;
else if (version == '12.2(2)XB8') flag++;
else if (version == '12.2(2)XB7') flag++;
else if (version == '12.2(2)XB6') flag++;
else if (version == '12.2(2)XB5') flag++;
else if (version == '12.2(2)XB3') flag++;
else if (version == '12.2(2)XB2') flag++;
else if (version == '12.2(2)XB15') flag++;
else if (version == '12.2(2)XB14') flag++;
else if (version == '12.2(2)XB11') flag++;
else if (version == '12.2(15)T9') flag++;
else if (version == '12.2(15)T8') flag++;
else if (version == '12.2(15)T7') flag++;
else if (version == '12.2(15)T5') flag++;
else if (version == '12.2(15)T4e') flag++;
else if (version == '12.2(15)T4') flag++;
else if (version == '12.2(15)T2') flag++;
else if (version == '12.2(15)T12') flag++;
else if (version == '12.2(15)T11') flag++;
else if (version == '12.2(15)T10') flag++;
else if (version == '12.2(15)T1') flag++;
else if (version == '12.2(15)T') flag++;
else if (version == '12.2(13)T9') flag++;
else if (version == '12.2(13)T8') flag++;
else if (version == '12.2(13)T5') flag++;
else if (version == '12.2(13)T4') flag++;
else if (version == '12.2(13)T3') flag++;
else if (version == '12.2(13)T2') flag++;
else if (version == '12.2(13)T13') flag++;
else if (version == '12.2(13)T12') flag++;
else if (version == '12.2(13)T11') flag++;
else if (version == '12.2(13)T10') flag++;
else if (version == '12.2(13)T1a') flag++;
else if (version == '12.2(13)T1') flag++;
else if (version == '12.2(13)T') flag++;
else if (version == '12.2(11)T9') flag++;
else if (version == '12.2(11)T8') flag++;
else if (version == '12.2(11)T6') flag++;
else if (version == '12.2(11)T5') flag++;
else if (version == '12.2(11)T4') flag++;
else if (version == '12.2(11)T3') flag++;
else if (version == '12.2(11)T2') flag++;
else if (version == '12.2(11)T11') flag++;
else if (version == '12.2(11)T10') flag++;
else if (version == '12.2(11)T1') flag++;
else if (version == '12.2(11)T') flag++;
else if (version == '12.2(8)T8') flag++;
else if (version == '12.2(8)T5') flag++;
else if (version == '12.2(8)T4') flag++;
else if (version == '12.2(8)T3') flag++;
else if (version == '12.2(8)T2') flag++;
else if (version == '12.2(8)T10') flag++;
else if (version == '12.2(8)T1') flag++;
else if (version == '12.2(8)T') flag++;
else if (version == '12.2(15)MC1c') flag++;
else if (version == '12.2(15)MC1b') flag++;
else if (version == '12.2(15)MC1a') flag++;
else if (version == '12.2(8)BY2') flag++;
else if (version == '12.2(8)BY1') flag++;
else if (version == '12.2(8)BY') flag++;
else if (version == '12.2(16)BX3') flag++;
else if (version == '12.2(16)BX2') flag++;
else if (version == '12.2(16)BX1') flag++;
else if (version == '12.2(16)BX') flag++;
else if (version == '12.2(16)B2') flag++;
else if (version == '12.2(16)B1') flag++;
else if (version == '12.2(16)B') flag++;
else if (version == '12.2(15)B') flag++;
else if (version == '12.1(5)YI2') flag++;
else if (version == '12.1(5)YI1') flag++;
else if (version == '12.1(5)YI') flag++;
else if (version == '12.1(5)YE5') flag++;
else if (version == '12.1(5)YE4') flag++;
else if (version == '12.1(5)YE3') flag++;
else if (version == '12.1(5)YE2') flag++;
else if (version == '12.1(5)YE1') flag++;
else if (version == '12.1(5)YD6') flag++;
else if (version == '12.1(5)YD5') flag++;
else if (version == '12.1(5)YD4') flag++;
else if (version == '12.1(5)YD3') flag++;
else if (version == '12.1(5)YD2') flag++;
else if (version == '12.1(5)YD1') flag++;
else if (version == '12.1(5)YD') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"telephony-service", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"call-manager-fallback", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
