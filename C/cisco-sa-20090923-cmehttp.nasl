#TRUSTED 736a6de5f86fb192734c708cd3fbc9562d593e989731e95a18a141f00a55c834047b2cdb3d0563e81105386540fbd4b94efe5304c9672909dba2e0a27d8bd1df0a562fe786d7b72518e846f9682d57aab285a4d7cfaaa1ac6674562aa3563dbe80fc58c74886a30c1296897d1ad601de6566db1df94bc5e467568d6ce0c5be99232526701a8831145890885949c35d1bc6fdd1405e829018681c3459257300970e930327e0bf3927675421c63b08ef47ef7f904fc77f2b69a2b0077d8df5a20f1ffbb7f5fbe426f97ffe980b99da403350b1948ab5fdbff281d92bd21c8f0e880d32a1424da6be9ae9f9b6a5f7f08eac0b6c0f385d71a1c0b3dde6761fa5e1edab17c3f3dc09f74e76a46224e22e31e1c35d1397c60aa48c96a539b8d3205dccf4905d0ecb78f27259b6512bda6d5d33ce1bccbf6a2a30b177bd203c88c9739021402bdde286bb43edd9334c498bb55560b5340fcbb46cd27e6db21f725503980bbdef3684b513abe151d1a11d5e2cfb4a5d38c640f5f39bf4088a3201fad766ea6b03e641d07dd520d9e64252a415c9cbd87ba0870c1b4684675a64d11fa3b2a8543ba182dcd50d92571b3d60fb794309a576c5521ed1dcb5496812fb6817fcc35b4ea25e27409df295a8ea448312df7e6965777e242b97a8f826610c63ed28d18bac611293a6bd08409ac60d8d9caa6a1b7ae124eeccc844a1eaf08332cdbc
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080af8116.shtml

include("compat.inc");

if (description)
{
 script_id(49041);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_cve_id("CVE-2009-2865");
 script_bugtraq_id(36498);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsq58779");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-cme");

 script_name(english:"Cisco Unified Communications Manager Express Vulnerability - Cisco Systems");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Cisco IOS devices that are configured for Cisco Unified
Communications Manager Express (CME) and the Extension Mobility feature
are affected by a buffer overflow vulnerability. Successful
exploitation of this vulnerability may result in the execution of
arbitrary code or a denial of service (DoS) condition on an affected
device.

Cisco has released free software updates that address this
vulnerability.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e53703ac");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080af8116.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9d520e5");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-cme.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

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

if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(15)XY3') flag++;
else if (version == '12.4(15)XY2') flag++;
else if (version == '12.4(15)XY1') flag++;
else if (version == '12.4(15)XY') flag++;
else if (version == '12.4(11)XW7') flag++;
else if (version == '12.4(11)XW6') flag++;
else if (version == '12.4(11)XW5') flag++;
else if (version == '12.4(11)XW3') flag++;
else if (version == '12.4(11)XW2') flag++;
else if (version == '12.4(11)XW1') flag++;
else if (version == '12.4(11)XW') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ephone ", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"logout-profile ", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
