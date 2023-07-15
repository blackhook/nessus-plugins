#TRUSTED 5cc98492f0f474845b23c7f9806a853a9c692abce138f5c4a9ff3f1390e12bf7e49c48d9f46ebf9b8ecdfd74d40b1ef7854467108dc9b39c6d841d956462ea60f1c13772fd56dbf5c48cc76297c3fbbad5cfbdf6342ced1309d1308c8ad75d836fb427e2e864f2645c9633a4960804e36fbb64d6a3a508fae47f49a3e50c4ffabfce593e9dd1db3ef372277dc968ab328ed835904ef6d5ecd2a032409a39137e5d17531b3d4b1e44ae2eef473e610646b3761c2c5ca22fcfa6b402e8165aff22e4a23c4512dc42eefc989118ac768fe23dd2ce80c234b89a9d19c522e64d7dbfb05556f55f3297f52a2af41081d9c225ace712a8f866cba1ce85cf542e845790e24dcb8757c2797f6aedad1be41f5c421b05490fbaa38161a29681cbcfd6f9df939d8ffd97892c6d3d7a8c2fba1544a3044f6fd6f3796c3d0f4f07f20f17cf603dbe3b3b842ff9842e62d8a65f9f18de14706cb17d77ce4f4a964bb2d5abc5f70a1a92e6f140a756806b3296176952b8a4356d99a9420aee4ab09f01480e8d16d1b3b055a26a94d796adac173fcd533873ff1db1cecb568722621ea1ae60cb1a6c7f4ecdf19b28f08fc5c0e6cfcd2a9a28171e53ac16b2bc0b301839d75956a4c66c6cc2576b2e1ff79ebe89426cbef22e0aa457fb473299c7cde03bd8468d6a19d134325bfc9f395540ec3505924fb1ee23046b0ef3ea6a4ef3865e2562679f
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00803be76e.shtml

include("compat.inc");

if (description)
{
 script_id(48981);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_cve_id("CVE-2005-0195");
 script_bugtraq_id(12368);
 script_xref(name:"CERT", value:"472582");
 script_xref(name:"CISCO-BUG-ID", value:"CSCed40933");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20050126-ipv6");

 script_name(english:"Multiple Crafted IPv6 Packets Cause Reload");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Cisco Internetwork Operating System (IOS) Software is vulnerable to a
Denial of Service (DoS) attack from crafted IPv6 packets when the
device has been configured to process IPv6 traffic. This vulnerability
requires multiple crafted packets to be sent to the device which may
result in a reload upon successful exploitation.

Cisco has made free software available to address this vulnerability.
There are workarounds available to mitigate the effects.");
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20050126-ipv6
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?881a9652");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00803be76e.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c59f7ef2");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20050126-ipv6.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/26");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/01/26");
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

# Affected: 12.0S
# 12.0(23)S and before are not vulnerable. This probably includes any rebuilds of 12.0(23)S (e.g. 12.0(23)S1)
if (
 check_release(version: version,
               patched: make_list("12.0(24)S6", "12.0(25)S3", "12.0(26)S2", "12.0(27)S1", "12.0(28)S"),
               oldest: "12.0(24)S") &&
 version != "12.0(23)S") {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.0(25)SX8") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.0(27)SZ") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# 12.2(2)B - 12.2(4)B7 Migrate to 12.2(13)T14 or later
if (check_release(version: version,
                  patched: make_list("12.2(4)B8"),
                  oldest:"12.2(2)B")) {
 report_extra = '\nUpdate to 12.2(13)T14 or later\n'; flag++;
}
# 12.2(4)B8 AND FWD Migrate to 12.3(7)T or later
if (
 deprecated_version(version, "12.2B") &&
 !check_release(version: version, patched: make_list("12.2(4)B8"))) {
 report_extra = '\nUpdate to 12.3(7)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2BC")) {
 report_extra = '\nUpdate to 12.3(9a)BC or later\n'; flag++;
}
if (deprecated_version(version, "12.2BX")) {
 report_extra = '\nUpdate to 12.3(7)XI1 or later\n'; flag++;
}
if (deprecated_version(version, "12.2BZ")) {
 report_extra = '\nUpdate to 12.3(7)XI1 or later\n'; flag++;
}
if (deprecated_version(version, "12.2CX")) {
 report_extra = '\nNo fix is planned for 12.2CX releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.2CZ")) {
 report_extra = '\nNo fix is planned for 12.2CZ releases. Upgrade to a supported release\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(18)EW1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2EWA
if (check_release(version: version,
                  patched: make_list("12.2(20)EWA") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(15)JK2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2MC")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(14)S9", "12.2(18)S5", "12.2(20)S3", "12.2(22)S1", "12.2(25)S") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(25)SE") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(14)SU1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(23)SV") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(23)SW") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2SW")) {
 report_extra = '\nUpdate to 12.2(17d)SXB2 or later\n'; flag++;
}
if (deprecated_version(version, "12.2SXA")) {
 report_extra = '\nUpdate to 12.2(17d)SXB1 or later\n'; flag++;
}
# only 12.2SXB affected
if ("SXB" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(17d)SXB1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SXD
# only 12.2SXD affected
if ("SXD" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(18)SXD") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2SY")) {
 report_extra = '\nUpdate to 12.2(17d)SXB2 or later\n'; flag++;
}
if (deprecated_version(version, "12.2SZ")) {
 report_extra = '\nUpdate to 12.2(20)S4 or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(13)T14", "12.2(15)T12") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2YT")) {
 report_extra = '\nUpdate to 12.2(15)T13 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YU")) {
 report_extra = '\nUpdate to 12.3(4)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YV")) {
 report_extra = '\nUpdate to 12.3(4)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YZ")) {
 report_extra = '\nUpdate to 12.2(20)S4 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZC")) {
 report_extra = '\nUpdate to 12.3(7)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZD")) {
 report_extra = '\nUpdate to 12.3(9) or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZE")) {
 report_extra = '\nUpdate to 12.3(9) or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZF")) {
 report_extra = '\nUpdate to 12.3(4)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZG")) {
 report_extra = '\nUpdate to 12.3(4)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZH")) {
 report_extra = '\nUpdate to 12.3(4)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZI")) {
 report_extra = '\nUpdate to 12.2(18)S or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZJ")) {
 report_extra = '\nUpdate to 12.3(9) or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZL")) {
 report_extra = '\nUpdate to 12.3(7)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZN")) {
 report_extra = '\nUpdate to 12.3(2)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZO")) {
 report_extra = '\nUpdate to 12.2(15)T12 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZP")) {
 report_extra = '\nUpdate to 12.3(8)XY or later\n'; flag++;
}
# Affected: 12.3
if (check_release(version: version,
                  patched: make_list("12.3(3f)", "12.3(5c)", "12.3(6a)", "12.3(9)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3BC
if (check_release(version: version,
                  patched: make_list("12.3(9a)BC") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.3(5a)B2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.3BW")) {
 report_extra = '\nUpdate to 12.3(5a)B2 or later\n'; flag++;
}
# Affected: 12.3JA
if (check_release(version: version,
                  patched: make_list("12.3(2)JA") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3T
if (check_release(version: version,
                  patched: make_list("12.3(2)T6", "12.3(4)T6", "12.3(7)T") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.3XA")) {
 report_extra = '\nUpdate to 12.3(7)T or later\n'; flag++;
}
if (deprecated_version(version, "12.3XB")) {
 report_extra = '\nUpdate to 12.3(8)T or later\n'; flag++;
}
if (deprecated_version(version, "12.3XC")) {
 report_extra = '\nUpdate to 12.3(2)XC3 or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.3(4)XD4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.3(2)XE1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.3XF")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.3(4)XG2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.3XH")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
# Affected: 12.3XI
if (check_release(version: version,
                  patched: make_list("12.3(7)XI") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.3(7)XJ") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.3(4)XK1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3XL
if (check_release(version: version,
                  patched: make_list("12.3(7)XL") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3XM
if (check_release(version: version,
                  patched: make_list("12.3(7)XM") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.3XN")) {
 report_extra = '\nUpdate to 12.3(14)T or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.3(4)XQ") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3XR
if (check_release(version: version,
                  patched: make_list("12.3(7)XR") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.3(7)XS") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.3(2)XT") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.3(8)XU") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3XX
if (check_release(version: version,
                  patched: make_list("12.3(8)XX") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3XW
if (check_release(version: version,
                  patched: make_list("12.3(8)XW") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3XY
if (check_release(version: version,
                  patched: make_list("12.3(8)XY") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3XZ
if (check_release(version: version,
                  patched: make_list("12.3(2)XZ") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3YA
if (check_release(version: version,
                  patched: make_list("12.3(8)YA") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3YD
if (check_release(version: version,
                  patched: make_list("12.3(8)YD") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3YE
if (check_release(version: version,
                  patched: make_list("12.3(4)YE") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3YF
if (check_release(version: version,
                  patched: make_list("12.3(11)YF") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3YG
if (check_release(version: version,
                  patched: make_list("12.3(8)YG") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3YH
if (check_release(version: version,
                  patched: make_list("12.3(8)YH") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"IPv6\s+is\s+enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
