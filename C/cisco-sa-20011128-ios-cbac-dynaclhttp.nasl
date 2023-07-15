#TRUSTED 71fa7ed3f90f6726d1af7378b78956e9c6b1e583125b34736b6df9cbd77cbba32169b187a0eb93a86e804a37c2b28293052240f74cbd73c76d8c939fcf04dcf9dc1e87be73d2488b81ed8aed4d1aa4c7fbaa3a5743e1076fbac2a9b8a3bb1634a8fa700e7f75387a3299bf49f91c13d28da15ea84c6128963466705b4fe4ddc60216f4581945243a786a5d25e63e50cc2312f42a365535a5a9ecb223d6fed79494006779efd54c0d0551ba0f4c832283598f567723256fd580a569d658bdfcd7bc92f999b880a79d0f81785c32427da676748ce83e04d7a231319bdc7172cdaff71dd32a8b9a91dde697dc27b6cb750672fe0ff7659b497bbd42e079f94e4c26577b8cf57ef9741f043b584387bf6492c3eb0361d10cd6f3afd858ee8fea9d6735b365297beb53a464479e802def9af1154df2eb5026f44892812965a7392b8fec8478eb2b26b3d13422799f2371ff9331b272dcf147981c824dd2713f6d48cb8778793913a61b8be247bc1fe7c834cadcc122303c3eaf51f0b53aa90b56e621d526baf91e88231294838f63cb662bf280c8137d7e485a6c29c57402ffb3b732f43c4bb55a02a8959af7d217f40aab44a1e5d70507faaf4d492dfdebaf4333a497d9d47d28a49525c80e4cbc858fbfd1e272615f7f7c47433191d7798ca3d29723732e072055711816080390b1c84ae8e0701261548b8f4d897e5e44522c2490
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00800941ee.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48962);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2001-0929");
 script_bugtraq_id(3588);
 script_xref(name:"CERT", value:"362483");
 script_name(english:"A Vulnerability in IOS Firewall Feature Set - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'The IOS Firewall Feature set, also known as Cisco Secure Integrated
Software, also known as Context Based Access Control (CBAC), and
introduced in IOS version 11.2P, has a vulnerability that permits
traffic normally expected to be denied by the dynamic access control
lists.
This vulnerability is documented as Cisco Bug ID CSCdv48261.
No other Cisco product is vulnerable.
There is no workaround.
');
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20011128-ios-cbac-dynacl
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d647aa2d");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00800941ee.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?b46bac85");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20011128-ios-cbac-dynacl.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/28");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/11/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv48261");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20011128-ios-cbac-dynacl");
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

# Affected: 11.2P
if (deprecated_version(version, "11.2P")) {
 report_extra = '\nUpdate to 12.0(20.3) or later\n'; flag++;
}
# Affected: 11.3T
if (deprecated_version(version, "11.3T")) {
 report_extra = '\nUpdate to 12.0(20.3) or later\n'; flag++;
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(20.3)", "12.0(21)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0T
if (deprecated_version(version, "12.0T")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XA
if (deprecated_version(version, "12.0XA")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XB
if (deprecated_version(version, "12.0XB")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XC
if (deprecated_version(version, "12.0XC")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XD
if (deprecated_version(version, "12.0XD")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XE
if (deprecated_version(version, "12.0XE")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XG
if (deprecated_version(version, "12.0XG")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XI
if (deprecated_version(version, "12.0XI")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XK
if (deprecated_version(version, "12.0XK")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XM
if (deprecated_version(version, "12.0XM")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XQ
if (deprecated_version(version, "12.0XQ")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XR
if (deprecated_version(version, "12.0XR")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XV
if (deprecated_version(version, "12.0XV")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(11a)", "12.1(11.1)", "12.1(12)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(8a)E5", "12.1(9.6)E", "12.1(10)E"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 report_extra = '\nUpdate to 12.2(5)7 or later\n'; flag++;
}
# Affected: 12.1XB
if (deprecated_version(version, "12.1XB")) {
 report_extra = '\nUpdate to 12.1(5)YB1 or later\n'; flag++;
}
# Affected: 12.1XC
if (deprecated_version(version, "12.1XC")) {
 report_extra = '\nUpdate to 12.2(5)7 or later\n'; flag++;
}
# Affected: 12.1XF
if (check_release(version: version,
                  patched: make_list("12.1(2)XF5") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XG
if (check_release(version: version,
                  patched: make_list("12.1(3)XG6") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XH
if (deprecated_version(version, "12.1XH")) {
 report_extra = '\nUpdate to 12.2(5)7 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XI")) {
 report_extra = '\nUpdate to 12.2(5)7 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XJ")) {
 report_extra = '\nUpdate to 12.1(5)YB or later\n'; flag++;
}
if (deprecated_version(version, "12.1XK")) {
 report_extra = '\nUpdate to 12.2(5)7 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XL")) {
 report_extra = '\nUpdate to 12.2(5)7 or later\n'; flag++;
}
# Affected: 12.1XM
if (check_release(version: version,
                  patched: make_list("12.1(5)XM6") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.1XP")) {
 report_extra = '\nUpdate to 12.2(5)T7 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XT")) {
 report_extra = '\nUpdate to 12.2(5)T7 or later\n'; flag++;
}
# Affected: 12.1YB
if (check_release(version: version,
                  patched: make_list("12.1(5)YB5") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YC
if (check_release(version: version,
                  patched: make_list("12.1(5)YC2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YE
if (check_release(version: version,
                  patched: make_list("12.1(5)YE4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YF
if (check_release(version: version,
                  patched: make_list("12.1(5)YF3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(5.7)", "12.2(6)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2DD")) {
 report_extra = '\nUpdate to 12.2(4)B or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(5.7)T", "12.2(8)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XD
if (check_release(version: version,
                  patched: make_list("12.2(2)XD3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XE
if (check_release(version: version,
                  patched: make_list("12.2(1)XE2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XH
if (check_release(version: version,
                  patched: make_list("12.2(2)XH2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XI
if (check_release(version: version,
                  patched: make_list("12.2(2)XI1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XJ
if (check_release(version: version,
                  patched: make_list("12.2(2)XJ1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XK
if (check_release(version: version,
                  patched: make_list("12.2(2)XK5") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XQ
if (check_release(version: version,
                  patched: make_list("12.2(2)XQ2") )) {
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
      if (preg(pattern:"ip\s+inspect\s+", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
