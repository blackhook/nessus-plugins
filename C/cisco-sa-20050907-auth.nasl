#TRUSTED 4ff51e9e0a3a1433d4a6e35e4bcd5a3bca7547c4de587d775ff303b94fb050aa90e8bcf56d4fb585c7342246960e27748d10fe4da39869c9a3cc5f3bf98eef07cb9cb1f97336625ad4676fc02c3b9de9329df9144a6bb3048e3dfe99e510a184f2aeb56db605a0acd779f406bf7932d68c68cbe2c79a685429344f0bc50259ddd4faf4dcd70513f8f834bb7e319b059b17d3d10e202f9670be06c8a96c62cc98c2ce32775a648243d043dcfbbf9d28d3a58c90af1157968674bfe48ed950721d8d4af1c436c711d543e02fca4ecf9bb8b65ca04248f211a7a1a1cbcc8c88b42865fa2d6c1abb83d36d133883cdb33706c311d78d083f6587da90fb40d95865099474a1e44b9ca4eb40ee133efa57f72d60cecd58ec9f0a6ae5c36c2e97c93029552b21cff341eb459434e705d72465bd6c8f0049bd861562fbe6cf5ac62366a8f6cb894505d0a7f53c4f6ba82ac1f4370f1fde6490551fe94fa127c78b8a2d3af147187398430a6e03e90cf5a6fda3de31c2087c1265b5614aa4c08972e4b4ba0d4a270b2fb444b5093c8fb9443d1e0fb39f24ef5e72e01b2c8e4a089d09b829d8c4dd3828e3307ffcc14399971a9a75281c0a3086f47b28f56d618c3586e4df437dd83b6043ce0e23f7192c80b905061db347e6980418b5865a4cebaa0729c4dee593c02e29288de094e3f53ef9359a86d8257c757bda706a9b073acec95922
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00805117cb.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48988);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2005-2841");
 script_bugtraq_id(14770);
 script_xref(name:"CERT", value:"236045");
 script_name(english:"Cisco IOS Firewall Authentication Proxy for FTP and Telnet Sessions Buffer Overflow");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'The Cisco IOS Firewall Authentication Proxy for FTP and/or Telnet
Sessions feature in specific versions of Cisco IOS software is
vulnerable to a remotely-exploitable buffer overflow condition.
Devices that do not support, or are not configured for Firewall
Authentication Proxy for FTP and/or Telnet Services are not affected.
Devices configured with only Authentication Proxy for HTTP and/or HTTPS
are not affected.
Only devices running certain versions of Cisco IOS are affected.
Cisco has made free software available to address this vulnerability.
There are workarounds available to mitigate the effects of the
vulnerability.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e45a1e2");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00805117cb.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?26a3c38c");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20050907-auth_proxy.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/07");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/09/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsa54608");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20050907-auth_proxy");
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

if (version == '12.3(11)YK') flag++;
else if (version == '12.3(8)YH') flag++;
else if (version == '12.3(8)YG1') flag++;
else if (version == '12.3(8)YG') flag++;
else if (version == '12.3(8)YD1') flag++;
else if (version == '12.3(8)YD') flag++;
else if (version == '12.3(8)YA1') flag++;
else if (version == '12.3(8)YA') flag++;
else if (version == '12.3(8)XX1') flag++;
else if (version == '12.3(8)XX') flag++;
else if (version == '12.3(7)XS2') flag++;
else if (version == '12.3(7)XS1') flag++;
else if (version == '12.3(7)XS') flag++;
else if (version == '12.3(7)XR3') flag++;
else if (version == '12.3(7)XR2') flag++;
else if (version == '12.3(7)XR') flag++;
else if (version == '12.3(4)XQ1') flag++;
else if (version == '12.3(4)XQ') flag++;
else if (version == '12.3(11)XL1') flag++;
else if (version == '12.3(11)XL') flag++;
else if (version == '12.3(4)XK3') flag++;
else if (version == '12.3(4)XK2') flag++;
else if (version == '12.3(4)XK1') flag++;
else if (version == '12.3(4)XK') flag++;
else if (version == '12.3(4)XG4') flag++;
else if (version == '12.3(4)XG3') flag++;
else if (version == '12.3(4)XG2') flag++;
else if (version == '12.3(4)XG1') flag++;
else if (version == '12.3(4)XG') flag++;
else if (version == '12.3(2)XF') flag++;
else if (version == '12.3(2)XE3') flag++;
else if (version == '12.3(2)XE2') flag++;
else if (version == '12.3(2)XE1') flag++;
else if (version == '12.3(2)XE') flag++;
else if (version == '12.3(4)XD4') flag++;
else if (version == '12.3(4)XD3') flag++;
else if (version == '12.3(4)XD2') flag++;
else if (version == '12.3(4)XD1') flag++;
else if (version == '12.3(4)XD') flag++;
else if (version == '12.3(2)XC2') flag++;
else if (version == '12.3(2)XC1') flag++;
else if (version == '12.3(2)XC') flag++;
else if (version == '12.3(2)XA4') flag++;
else if (version == '12.3(2)XA3') flag++;
else if (version == '12.3(2)XA2') flag++;
else if (version == '12.3(2)XA1') flag++;
else if (version == '12.3(2)XA') flag++;
else if (version == '12.3(11)T5') flag++;
else if (version == '12.3(11)T4') flag++;
else if (version == '12.3(11)T3') flag++;
else if (version == '12.3(11)T2') flag++;
else if (version == '12.3(11)T') flag++;
else if (version == '12.3(8)T8') flag++;
else if (version == '12.3(8)T7') flag++;
else if (version == '12.3(8)T6') flag++;
else if (version == '12.3(8)T5') flag++;
else if (version == '12.3(8)T4') flag++;
else if (version == '12.3(8)T3') flag++;
else if (version == '12.3(8)T1') flag++;
else if (version == '12.3(8)T') flag++;
else if (version == '12.3(7)T9') flag++;
else if (version == '12.3(7)T8') flag++;
else if (version == '12.3(7)T7') flag++;
else if (version == '12.3(7)T6') flag++;
else if (version == '12.3(7)T4') flag++;
else if (version == '12.3(7)T3') flag++;
else if (version == '12.3(7)T2') flag++;
else if (version == '12.3(7)T1') flag++;
else if (version == '12.3(7)T') flag++;
else if (version == '12.3(4)T9') flag++;
else if (version == '12.3(4)T8') flag++;
else if (version == '12.3(4)T7') flag++;
else if (version == '12.3(4)T6') flag++;
else if (version == '12.3(4)T4') flag++;
else if (version == '12.3(4)T3') flag++;
else if (version == '12.3(4)T2') flag++;
else if (version == '12.3(4)T11') flag++;
else if (version == '12.3(4)T10') flag++;
else if (version == '12.3(4)T1') flag++;
else if (version == '12.3(4)T') flag++;
else if (version == '12.3(2)T9') flag++;
else if (version == '12.3(2)T8') flag++;
else if (version == '12.3(2)T7') flag++;
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
else if (version == '12.3(13)') flag++;
else if (version == '12.3(12a)') flag++;
else if (version == '12.3(12)') flag++;
else if (version == '12.3(10c)') flag++;
else if (version == '12.3(10b)') flag++;
else if (version == '12.3(10a)') flag++;
else if (version == '12.3(10)') flag++;
else if (version == '12.3(9c)') flag++;
else if (version == '12.3(9b)') flag++;
else if (version == '12.3(9a)') flag++;
else if (version == '12.3(9)') flag++;
else if (version == '12.3(6c)') flag++;
else if (version == '12.3(6b)') flag++;
else if (version == '12.3(6a)') flag++;
else if (version == '12.3(6)') flag++;
else if (version == '12.3(5d)') flag++;
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
else if (version == '12.2(15)ZL1') flag++;
else if (version == '12.2(15)ZL') flag++;
else if (version == '12.2(13)ZH5') flag++;
else if (version == '12.2(13)ZH4') flag++;
else if (version == '12.2(13)ZH3') flag++;
else if (version == '12.2(13)ZH2') flag++;
else if (version == '12.2(13)ZH1') flag++;
else if (version == '12.2(13)ZH') flag++;
else if (version == '12.2(13)ZF2') flag++;
else if (version == '12.2(13)ZF1') flag++;
else if (version == '12.2(13)ZF') flag++;
else if (version == '12.2(18)SXF4') flag++;
else if (version == '12.2(18)SXF3') flag++;
else if (version == '12.2(18)SXF2') flag++;
else if (version == '12.2(18)SXF1') flag++;
else if (version == '12.2(18)SXF') flag++;
else if (version == '12.2(33)SRA') flag++;
else if (version == '12.2(31)SG') flag++;
else if (version == '12.2(25)SG') flag++;
else if (version == '12.2(25)SEC2') flag++;
else if (version == '12.2(25)SEC1') flag++;
else if (version == '12.2(25)SEC') flag++;
else if (version == '12.2(18)IXB') flag++;
else if (version == '12.2(18)IXA') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip\s+auth-proxy\s+", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
