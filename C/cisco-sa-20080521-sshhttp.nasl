#TRUSTED 8709d00b8aa6cc42288677e4e9cf3ff06fd649e1a6be98be8a2db9f390552003aa7bf4d2a5a577bfea6f5456cc64268afe47ccb42648efd3bfe9701c3ff0162e550b495bf488ed647e8d514f7b2ac1f7710121b0c1415c5910d44064b08870b57a08f1ea8aed4e6d1cb7c90613d7caa3c7124e314ad1630bc04f6b7f5e544ca1bc755f420960da35036b245fe2d9b2de2bcebc29fe68663aede08034dd68f92618a59cbc720c0fe7e754ab8d729803cbd072dca947ba62eec69b383491119311b17af927e39cf055f220e2f79cc0d46a84e357372a460d156f158e2d58bb6566d6f6087579b27e096135ff8c6dfed2cf5ff6a685d9f0732e26a7ca331b88036c4749a83fd422cd80af673e9bbd2c3e54c722d278e37105fc090048fba1a27254a1c4b6eb9ff228fe486de2f6814284814835d0bacf9536c31c2e34df75a88cf39d06e153af28e69f4ffc146d93983bab4961db9706aa29dc748ca19d9ae37f6726b9146180a2d12544618eb2e15f3adb0c3f37680b28477c8dd10aea98e79f9c6a49a5ebbb4874067a4520855188eb2b3be26e8657fe564c9bfbdb26b025f5b239aa77d0f12ce05319db7ad0eca2ee3e3af28e046d68a6b0c8349c9a21290686c6715a646984f8ebe25899ba4ea83aa8040957a2f2554bc9e0b2c0b3b9081ef0ebfe1653df19af2ff7677c04f2f48b9f2ed91e5920e99b2b425ac4804b5321ff
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a008099567f.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49015);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2008-1159");
 script_bugtraq_id(29314);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsh51293");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsk42419");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsk60020");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080521-ssh");
 script_name(english:"Cisco IOS Secure Shell Denial of Service Vulnerabilities - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'The Secure Shell server (SSH) implementation in Cisco IOS contains
multiple vulnerabilities that allow unauthenticated users the ability
to generate a spurious memory access error or, in certain cases, reload
the device.
The IOS SSH server is an optional service that is disabled by default,
but its use is highly recommended as a security best practice for
management of Cisco IOS devices. SSH can be configured as part of the
AutoSecure feature in the initial configuration of IOS devices.
AutoSecure runs after initial configuration, or manually. SSH is enabled
any time RSA keys are generated such as when a http secure-server or
trust points for digital certificates are configured. Devices that are
not configured to accept SSH connections are not affected by these
vulnerabilities.'
 );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44a6b3b8");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a008099567f.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?d779558e");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080521-ssh.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:C/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/21");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.4(11)XW6') flag++;
else if (version == '12.4(11)XW5') flag++;
else if (version == '12.4(11)XW4') flag++;
else if (version == '12.4(11)XW3') flag++;
else if (version == '12.4(11)XW2') flag++;
else if (version == '12.4(11)XW1') flag++;
else if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(14)XK') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(15)XF') flag++;
else if (version == '12.4(6)XE3') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(15)T1') flag++;
else if (version == '12.4(15)T') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T5') flag++;
else if (version == '12.4(9)T4') flag++;
else if (version == '12.4(9)T3') flag++;
else if (version == '12.4(9)T2') flag++;
else if (version == '12.4(9)T1') flag++;
else if (version == '12.4(9)T') flag++;
else if (version == '12.4(15)SW') flag++;
else if (version == '12.4(11)SW3') flag++;
else if (version == '12.4(11)SW2') flag++;
else if (version == '12.4(11)SW1') flag++;
else if (version == '12.4(11)SW') flag++;
else if (version == '12.4(16)MR1') flag++;
else if (version == '12.4(16)MR') flag++;
else if (version == '12.4(12)MR2') flag++;
else if (version == '12.4(12)MR1') flag++;
else if (version == '12.4(12)MR') flag++;
else if (version == '12.4(11)MR') flag++;
else if (version == '12.4(13d)JA') flag++;
else if (version == '12.4(17)') flag++;
else if (version == '12.4(16a)') flag++;
else if (version == '12.4(16)') flag++;
else if (version == '12.4(13e)') flag++;
else if (version == '12.4(13d)') flag++;
else if (version == '12.4(13c)') flag++;
else if (version == '12.4(13b)') flag++;
else if (version == '12.4(13a)') flag++;
else if (version == '12.4(13)') flag++;
else if (version == '12.4(12c)') flag++;
else if (version == '12.4(12b)') flag++;
else if (version == '12.4(12a)') flag++;
else if (version == '12.4(12)') flag++;
else if (version == '12.4(10c)') flag++;
else if (version == '12.4(10b)') flag++;
else if (version == '12.4(10a)') flag++;
else if (version == '12.4(10)') flag++;
else if (version == '12.4(8d)') flag++;
else if (version == '12.4(8c)') flag++;
else if (version == '12.4(8b)') flag++;
else if (version == '12.4(8a)') flag++;
else if (version == '12.4(8)') flag++;
else if (version == '12.4(7h)') flag++;
else if (version == '12.4(7g)') flag++;
else if (version == '12.4(7f)') flag++;
else if (version == '12.4(7e)') flag++;
else if (version == '12.4(7d)') flag++;
else if (version == '12.4(7c)') flag++;
else if (version == '12.4(7b)') flag++;
else if (version == '12.4(7a)') flag++;
else if (version == '12.4(7)') flag++;


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ssh", "show ip ssh");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SSH Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
