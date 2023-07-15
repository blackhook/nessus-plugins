#TRUSTED 2430f4df3d62206f38a3d7d09cd211eeb3e91a7fb700e256384c4c7c625021dc8c86720bd112e224fa2eb56a7d12e3a1f5cb0805fcc134102f7db96d37ac5cb3629a491fc42c8cd3f90a7fbb99df3f0d325f7f335016677dbf58cc8fa02ded27c62d2e8a1c4c3c321dd8fefe0c805521aa0e9074f9e92678d8e2c678cf0a29648f2121dcdbf2c6b576c0ebc3ee762cca51784d204f45102fdeb2937c30a697e35d425757ebea6f44b896cd064c5902b3414ca3485635c551405feaf9a52974633b2fb532a8a0eff134707928bf0555ea3cd9cf57f4dce2a1e42e534a01912b9d16659e5294e5f0136041f5d91f5f63834b1ef3ca193ba0dda2c11e0b010ca34e4ac825933c5d5ae65c154b0e4142eb8671690ea28ad15194ed420f625fa93d4769968011211eeda7eef279cf4d83ee55732237f5d52682166065af01a96fbd003e784da6ce7dd4fa691792363b40d589d447edce11d96a8389f61c467c0270bbc7c5894c8a459c92b5209731245d8e08b197461576e0256863a92dedee02a07567a90a084eca243fe1f846404557d1843a51cf34214a2eaeb77a929fac5a32f27b24c2da92efd9480e4c6c2d5b971c96ab4c6fa78e344a798a46c9b4c2b7f2fdddc5524ed60a1912d1a83fe22cf9632f71a37c03df24849ddb14d17f9c2eb14c0e0024b0ea39cb16f77e3e2d309ed3609c47f57c6fec46af3f657f378d0e933c
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080b4095e.shtml

include("compat.inc");

if (description)
{
 script_id(49056);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_cve_id("CVE-2010-2827");
 script_bugtraq_id(42426);
 script_xref(name:"CISCO-BUG-ID", value:"CSCti18193");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20100812-tcp");

 script_name(english:"Cisco IOS Software TCP Denial of Service Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
"Cisco IOS Software Release, 15.1(2)T is affected by a denial of
service (DoS) vulnerability during the TCP establishment phase. The
vulnerability could cause embryonic TCP connections to remain in a
SYNRCVD or SYNSENT state. Enough embryonic TCP connections in these
states could consume system resources and prevent an affected device
from accepting or initiating new TCP connections, including any
TCP-based remote management access to the device. No authentication is
required to exploit this vulnerability. An attacker does not need to
complete a three-way handshake to trigger this vulnerability;
therefore, this vulnerability can be exploited using spoofed packets.
This vulnerability may be triggered by normal network traffic. Cisco
has released Cisco IOS Software Release 15.1(2)T0a to address this
vulnerability.");
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100812-tcp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00adfcb2");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080b4095e.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?506a7b32");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100812-tcp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2010/08/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2018 Tenable Network Security, Inc.");
 script_family(english:"CISCO");

 script_dependencies("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");

 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Affected: 15.1T
# Releases prior to 15.1(2)T are not vulnerable.
if (check_release(version: version,
                  patched: make_list("15.1(2)T0a", "15.1(2)T1"),
                  oldest:"15.1(2)T")) { flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_tcp_brief_all", "show tcp brief all");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SYNRCVD", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"SYNSENT", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    buf = cisco_command_kb_item("Host/Cisco/Config/debug_ip_tcp_transactions", "debug ip tcp transactions");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"connection queue limit reached\s+:port", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"No wild listener:\s+port", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
