#TRUSTED 31650794e702eef1a7c28ad82e560bf71a23bd0be246708f5f6f9f606089897ae4c3a5fddbe42f990de88bbec7638221f9735762d8c54caaefed3d385fac67b1b80a30b56206dfadacd85869d873318eb87ffdf6e2e07bf63de954745b978eb139249772eaf64852eb41cc332940a70275f3337a3d46f08b7b7fbe7140adabaace0ba5e194fd644ebcac3583907f9cf0655e1ee36f6ea12fc993df3c71dcd38b55b8ee39ad38c723c92bb3090f0d42674c404c8e9dcf1a000feb31b061d2db953737211c13167610487cdb320e7c09a9562adda0ea772b2f54b8f3a4321e87d40329bf87bab27180aca6bb080c62c464277289ebe0146c9a4afb22e9712647fc839644a9ea9d131344fdfab13400cc6b40af3bd068901dc60b62a9044bb7574ac344141128df133cc0fc4badfee102659ffe9a63e2c94c98dccb907e1abb22746838dea64ea7da2b3a3c147396515a1f6c531708c773023d7ff7fcfc88fb2af067b6e709cf669cce55991554eef679b8e7e2eabc90eaa0a23a9d4f335ccd8f51f982805458ae8cd928c8261250091a2e21bea7bea139c833d4fa36683141f092f211fa11b4c6af3283b17dc21cbeecbe9169a1c47966fa76a45230578b1d66cae26a7752f33fda3cf3d8ec381ba5cdc17e922ffc152816991fda1d0fd45d566789452cdce7a4c6cb49342aab05ad15192829a0feca2ef103ec095d1481c3d71a
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080899636.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49009);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2007-4263");
 script_bugtraq_id(25240);
 script_name(english:"Cisco IOS Secure Copy Authorization Bypass Vulnerability");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'The server side of the Secure Copy (SCP) implementation in Cisco
Internetwork Operating System (IOS) contains a vulnerability that
allows any valid user, regardless of privilege level, to transfer files
to and from an IOS device that is configured to be a Secure Copy
server. This vulnerability could allow valid users to retrieve or write
to any file on the device\'s filesystem, including the device\'s saved
configuration. This configuration file may include passwords or other
sensitive information.
 The IOS Secure Copy Server is an optional service that is disabled by
default. Devices that are not specifically configured to enable the IOS
Secure Copy Server service are not affected by this vulnerability.
 This vulnerability does not apply to the IOS Secure Copy Client
feature.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6281a98b");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080899636.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?fde51b32");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070808-scp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/08/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsc19259");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20070808-scp");
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

if (version == '12.2(18)ZU2') flag++;
else if (version == '12.2(18)ZU1') flag++;
else if (version == '12.2(18)ZU') flag++;
else if (version == '12.2(18)SXF8') flag++;
else if (version == '12.2(18)SXF7') flag++;
else if (version == '12.2(18)SXF6') flag++;
else if (version == '12.2(18)SXF5') flag++;
else if (version == '12.2(18)SXF4') flag++;
else if (version == '12.2(18)SXF3') flag++;
else if (version == '12.2(18)SXF2') flag++;
else if (version == '12.2(18)SXF1') flag++;
else if (version == '12.2(18)SXF') flag++;
else if (version == '12.2(18)SXE6b') flag++;
else if (version == '12.2(18)SXE6a') flag++;
else if (version == '12.2(18)SXE6') flag++;
else if (version == '12.2(18)SXE5') flag++;
else if (version == '12.2(18)SXE4') flag++;
else if (version == '12.2(18)SXE3') flag++;
else if (version == '12.2(18)SXE2') flag++;
else if (version == '12.2(18)SXE1') flag++;
else if (version == '12.2(18)SXE') flag++;
else if (version == '12.2(18)SXD7b') flag++;
else if (version == '12.2(18)SXD7a') flag++;
else if (version == '12.2(18)SXD7') flag++;
else if (version == '12.2(18)SXD6') flag++;
else if (version == '12.2(18)SXD5') flag++;
else if (version == '12.2(18)SXD4') flag++;
else if (version == '12.2(18)SXD3') flag++;
else if (version == '12.2(18)SXD2') flag++;
else if (version == '12.2(18)SXD1') flag++;
else if (version == '12.2(18)SXD') flag++;
else if (version == '12.2(18)IXD') flag++;
else if (version == '12.2(18)IXC') flag++;
else if (version == '12.2(18)IXB2') flag++;
else if (version == '12.2(18)IXB1') flag++;
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
      if (preg(pattern:"ip scp server enable", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
