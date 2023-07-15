#TRUSTED a2c848e0ecf52185ad933a07ab37202bbd9bd9b4d71062fa732d08d53b9f70f130e23e0d0b4a17b27b73637fcccbc320b95c0e3be05f23fe0f98ae00934362e3ff5f778a82a8f52da13dc8d5b12a20137547c25074ef15d4b73418302b4a0870c8ae9c5a8b70d6dc48982ef9c6bab174ca157892ccba8ac6fdba43e0a2806416c95a5a77840fa9a69adddf8a4127ec261e9df2e2d33cd80327ca817cee5b41007c975bb2b2f05eae40cd47f4784f4a40c26ab1b031dbcfa011ae147663db1dad18863e5c396ce20c10bddac8c745e933d737908ac25bed7dcad101ee460c4b9a2e0071d92939e42add962e628a3af4f29f32545fd2badb93bdc1d111589775b98a5cc4c2c35335ca0f5b76515d80affe9d7b827f44e091284646c3c5f838070cd32c492c2df938c9f279ef02e0d9eba1242a1934c0ba3f490f7d7ecd0c8f751b2de28dc51e72fca3fc844c417699f543774e71b192da7577c3d9f8f9143b2b21f49cb351fdf889fe21ee81a192a723782a6bf4526336e03b465e3f3d04be80a80470280ab7caebfeea4b6c7db8f5dcfcc63160bc71641f4691387f92c9c43096f27d5381bdfe183e8ff55fb4a4a2b07a5c80c1a2664ffa84df8a333fb94b496ed7a41b8d8c09a712ceebdf3057e2e7209849a23e1897ff78dedaf135dbf8e8daef1ed1c34783b633e49c8a87a882658c3eb2e8300a874cb7728a448601a8cf4e
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00800b1695.shtml

include("compat.inc");

if (description)
{
 script_id(48958);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_cve_id("CVE-2001-1183");
 script_bugtraq_id(3022);
 script_xref(name:"CERT", value:"656315");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt46181");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20010712-pptp");

 script_name(english:"Cisco IOS PPTP Vulnerability - Cisco Systems");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Point-to-Point Tunneling Protocol (PPTP) allows users to tunnel to an
Internet Protocol (IP) network using a Point-to-Point Protocol (PPP).
The protocol is described in RFC2637.

PPTP implementation using Cisco IOS software releases contains a
vulnerability that will crash a router if it receives a malformed or
crafted PPTP packet. To expose this vulnerability, PPTP must be enabled
on the router. PPTP is disabled by default. No additional special
conditions are required.

This vulnerability is present in all Cisco IOS releases that support
PPTP. PPTP is supported in the following software releases:
No other Cisco product is vulnerable.

There is no workaround for this vulnerability.");
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20010712-pptp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4797061");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00800b1695.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3a7dd2d");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20010712-pptp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/07/12");
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
report_extra = "";
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(7a)E1", "12.1(8a)E", "12.1(9)E"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EZ
if (check_release(version: version,
                  patched: make_list("12.1(6)EZ2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 report_extra = '\nUpdate to 12.2(3) or later\n'; flag++;
}
# Affected: 12.1XM
if (check_release(version: version,
                  patched: make_list("12.1(5)XM4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XV
if (check_release(version: version,
                  patched: make_list("12.1(5)XV3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YA
if (deprecated_version(version, "12.1YA")) {
 report_extra = '\nUpdate to 12.2(2)XB or later\n'; flag++;
}
# Affected: 12.1YB
if (check_release(version: version,
                  patched: make_list("12.1(5)YB4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YC
if (check_release(version: version,
                  patched: make_list("12.1(5)YC1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YD
if (check_release(version: version,
                  patched: make_list("12.1(5)YD2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(1.1)", "12.2(3)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(4)T") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XA
if (check_release(version: version,
                  patched: make_list("12.2(2)XA") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XD
if (check_release(version: version,
                  patched: make_list("12.2(1)XD1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XE
if (check_release(version: version,
                  patched: make_list("12.2(1)XE") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XH
if (check_release(version: version,
                  patched: make_list("12.2(1)XH") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XQ
if (check_release(version: version,
                  patched: make_list("12.2(1)XQ") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"protocol\s+pptp", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_warning(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
