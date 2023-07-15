#TRUSTED 61d63167ea4ff0f5099fb85ba5f16ddbedb65bf783c65d726aaffdb773d27cec17886b69a68ccade37ea538090e5364283a48d935e6e1e7cd35b6c9ed1ee199e42b8fc77baf3d765dbf672b350c5029ccbaf0ffedce0c155b3582d6aeca0138b1534fee04813655191f3d45b4001d2e48f613b86c3f17e78debb78352e67c6d9fada18142c61af384b932c4bf391713e5e59a6a679500f65d6c3142f942e01c73cbc4ce772dbfa2a6b3e6793eda3d28ad8f097f3823d1e4eeeb916d8c0268f68022b4cd8bd622793bbe676538cd26b41dfde888e9c0c83f9ffa053b43e3f801c0261304d418ecf1a95ad6eb6ca16fa23fec89e32d5dda3287a7781276cbbb5c950d60241c67785bfc8dde016f98546216430d3a9f85a1a53ab0677344cdfb7d96f3fc9e04bfbf12e15f529f5af9233d6806991dca23c8dbd860c1d2b61924f0724fa60f4a1794d8bbcd810046eef849751c4a9c3a6239c70344a3e08e61072628064a9684f7f3933d707d44ab15c35ccf627f94f6bca0dbfabf2144bbf5ec94247150666ab7dccd0346c25184d5f9c6fe2913c99aabbdfc40465d1890c713b74f92c23290eee39b4a66af850753f7e30801c8a5e668069fa2415867ba47cc5ad43523f52b0748c911b74aff0c81769218f9aec1ca9045c1fb4a49bd6b20f56d0584c03ccd573c0f25d996f4a750780d15bf0e7a8de87fee5b0bd0e4b02821c98
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120926-bgp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(62370);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2012-4617");
  script_bugtraq_id(55694);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt35379");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120926-bgp");

  script_name(english:"Cisco IOS Software Malformed Border Gateway Protocol Attribute Vulnerability (cisco-sa-20120926-bgp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a vulnerability in the Border Gateway
Protocol (BGP) routing protocol feature. The vulnerability can be
triggered when the router receives a malformed attribute from a peer
on an existing BGP session. Successful exploitation of this
vulnerability can cause all BGP sessions to reset. Repeated
exploitation may result in an inability to route packets to BGP
neighbors during reconvergence times. Cisco has released free software
updates that address this vulnerability. There are no workarounds for
this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120926-bgp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d72b44e0"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120926-bgp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/28");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");
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
if ( version == '15.2(1)S' ) flag++;
if ( version == '15.2(1)S1' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_bgp_neighbors", "show ip bgp neighbors");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"neighbor", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
