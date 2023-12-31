#TRUSTED a1ff451f173681863787e6ad36a0bf372329faac3d0fa4b74d14b5b004f843cf7521d5f370e73ebc9f7d57c75286eb7bc7ea92d16172f0053a51d09f32dd1405961be8e17f7e6571818d6868e62938df47fbbe83ed9794b1b78f46d246e46220fb234796b5bdfb44d2def3ab9ecac4628ba0949bf8fd11844a4eb06f7c031376c03dbc7220a000b1e4ecd39c43f3cf71597049c77e2d921605d860f3383cdce45b6c3801362dd78607a2eb962fa8f509b736738992a18c4ee8d5b60b613fb23d1399e646e60160569d0ccd2becb8d78d1ba1de6226dbff73e2ca0bab8374e9a9cc2440bfc845c1627a3dec795c5452c0563ac43d671f6ce88154285f1be11af3d413ab697f90414a1ee97cb289ca7ac6815f3026b6da123a4d063ac6afdfd26486b3cb1836aace84939199cce1d8768dd8ac45df9ff9a349419b6c9393b5cea4d87e6b203d31695987230d773a465c047179262730ebe29ed30e95f7544672efdca463bd31b605ee765ebd869a43522125150d47184011a3b56bea34447ff70fd67388bca1079e76792357b7f586063c47d874fe22e505f2fc82ce88d1ee50796866fd799ec425225af926b5ec169bd2c9a2566460264925ce7a4c632e58ff5ee2772d9da77a45ca16e3455f39760ed8be52a7cc2428b4e7c9a3300e5ea0bd215ae821c0df9f93cd8b2ec9ee6d2eddc7bd06664a1eaefcb2f91d9a948fbf4c4d
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080237a05.shtml

include("compat.inc");

if (description)
{
 script_id(48975);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2004-0589");
 script_bugtraq_id(10560);
 script_xref(name:"CERT", value:"784540");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu53656");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx23494");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea28131");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20040616-bgp");

 script_name(english:"Cisco IOS Malformed BGP Packet Causes Reload - Cisco Systems");
 script_summary(english:"Checks the IOS version.");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'A Cisco device running IOS and enabled for the Border Gateway Protocol
(BGP) is vulnerable to a Denial of Service (DOS) attack from a
malformed BGP packet. The BGP protocol is not enabled by default, and
must be configured in order to accept traffic from an explicitly
defined peer. Unless the malicious traffic appears to be sourced from a
configured, trusted peer, it would be difficult to inject a malformed
packet.
Cisco has made free software available to address this problem.
');
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20040616-bgp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cc52d23");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080237a05.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?d48a5776");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20040616-bgp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/16");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/06/16");
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

if (deprecated_version(version, "11.1")) {
 report_extra = '\nUpdate to 11.2(26g) or later\n'; flag++;
}
if (deprecated_version(version, "11.1AA")) {
 report_extra = '\nUpdate to 11.2(26)P7 or later\n'; flag++;
}
if (deprecated_version(version, "11.1CA")) {
 report_extra = '\nUpdate to 12.0(27) or later\n'; flag++;
}
if (deprecated_version(version, "11.1CC")) {
 report_extra = '\nUpdate to 12.0(27) or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("11.2(26g)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("11.2(26)P7") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("11.3(11f)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("11.3(11b)T5") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(27)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0DA")) {
 report_extra = '\nUpdate to 12.2(12)DA6 or later\n'; flag++;
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(21)S7", "12.0(22)S2e", "12.0(22)S3c", "12.0(22)S4a", "12.0(22)S5", "12.0(23)S3", "12.0(24)S2", "12.0(25)S1", "12.0(26)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0SL")) {
 report_extra = '\nUpdate to 12.0(23)S3 or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(17)ST10", "12.0(21)ST7") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0SV
if (check_release(version: version,
                  patched: make_list("12.0(27)SV") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.0(25)SX") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0SZ
if (check_release(version: version,
                  patched: make_list("12.0(23)SZ3", "12.0(26)SZ") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0T")) {
 report_extra = '\nUpdate to 12.1(20) or later\n'; flag++;
}
if (
 "W5" >< version && # avoid flagging versions like W4
 check_release(version: version, patched: make_list("12.0(16)W5(21c)", "12.0(25)W5(27b)", "12.0(26)W5(28a)", "12.0(27)W5(29)"))
) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0WX")) {
 report_extra = '\nUpdate to 12.0W5 or later\n'; flag++;
}
if (deprecated_version(version, "12.0XA")) {
 report_extra = '\nUpdate to 12.1(20) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XC")) {
 report_extra = '\nUpdate to 12.1(20) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XD")) {
 report_extra = '\nUpdate to 12.1(20) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XE")) {
 report_extra = '\nUpdate to 12.1(20)E or later\n'; flag++;
}
if (deprecated_version(version, "12.0XG")) {
 report_extra = '\nUpdate to 12.1(20) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XH")) {
 report_extra = '\nUpdate to 12.1(20) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XI")) {
 report_extra = '\nUpdate to 12.1(20) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XJ")) {
 report_extra = '\nUpdate to 12.1(20) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XK")) {
 report_extra = '\nUpdate to 12.1(5)T19 or later\n'; flag++;
}
if (deprecated_version(version, "12.0XL")) {
 report_extra = '\nUpdate to 12.2(17) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XN")) {
 report_extra = '\nUpdate to 12.1(20) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XR")) {
 report_extra = '\nUpdate to 12.2(17) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XS")) {
 report_extra = '\nUpdate to 12.1(20)E or later\n'; flag++;
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(20)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.1AA")) {
 report_extra = '\nUpdate to 12.2(17) or later\n'; flag++;
}
# Affected: 12.1AZ
if (check_release(version: version,
                  patched: make_list("12.1(14)AZ") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.1DA")) {
 report_extra = '\nUpdate to 12.2(12)DA6 or later\n'; flag++;
}
if (deprecated_version(version, "12.1DB")) {
 report_extra = '\nUpdate to 12.2(15)B1 or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(6)E12.0", "12.1(8b)E14", "12.1(11b)E12.0", "12.1(12c)E7", "12.1(13)E6", "12.1(14)E4", "12.1(19)E", "12.1(20)E") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EA
if (check_release(version: version,
                  patched: make_list("12.1(14)EA1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EB
if (check_release(version: version,
                  patched: make_list("12.1(14)EB1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(19)EC") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EO
if (check_release(version: version,
                  patched: make_list("12.1(19)EO") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EV
if (check_release(version: version,
                  patched: make_list("12.1(12c)EV2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EW
if (check_release(version: version,
                  patched: make_list("12.1(19)EW") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.1EX")) {
 report_extra = '\nUpdate to 12.1(14)E4 or later\n'; flag++;
}
if (deprecated_version(version, "12.1EY")) {
 report_extra = '\nUpdate to 12.1(14)E4 or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.1(5)T19") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.1XA")) {
 report_extra = '\nUpdate to 12.1(5)T19 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XB")) {
 report_extra = '\nUpdate to 12.1(5)T19 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XC")) {
 report_extra = '\nUpdate to 12.1(5)T19 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XD")) {
 report_extra = '\nUpdate to 12.2(17) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XE")) {
 report_extra = '\nUpdate to 12.1(20)E or later\n'; flag++;
}
if (deprecated_version(version, "12.1XF")) {
 report_extra = '\nUpdate to 12.2(4)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XG")) {
 report_extra = '\nUpdate to 12.2(4)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XH")) {
 report_extra = '\nUpdate to 12.2(17) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XI")) {
 report_extra = '\nUpdate to 12.2(17) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XJ")) {
 report_extra = '\nUpdate to 12.2(4)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XL")) {
 report_extra = '\nUpdate to 12.2T or later\n'; flag++;
}
if (deprecated_version(version, "12.1XM")) {
 report_extra = '\nUpdate to 12.2T or later\n'; flag++;
}
if (deprecated_version(version, "12.1XP")) {
 report_extra = '\nUpdate to 12.2(4)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XQ")) {
 report_extra = '\nUpdate to 12.2T or later\n'; flag++;
}
if (deprecated_version(version, "12.1XR")) {
 report_extra = '\nUpdate to 12.2T or later\n'; flag++;
}
if (deprecated_version(version, "12.1XT")) {
 report_extra = '\nUpdate to 12.2(4)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XU")) {
 report_extra = '\nUpdate to 12.2T or later\n'; flag++;
}
if (deprecated_version(version, "12.1XV")) {
 report_extra = '\nUpdate to 12.2(2)XB16 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XY")) {
 report_extra = '\nUpdate to 12.2(2)XB16 or later\n'; flag++;
}
if (deprecated_version(version, "12.1YA")) {
 report_extra = '\nUpdate to 12.2(8)T10 or later\n'; flag++;
}
if (deprecated_version(version, "12.1YB")) {
 report_extra = '\nUpdate to 12.2(4)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.1YC")) {
 report_extra = '\nUpdate to 12.2(8)T10 or later\n'; flag++;
}
if (deprecated_version(version, "12.1YD")) {
 report_extra = '\nUpdate to 12.2(8)T10 or later\n'; flag++;
}
if (deprecated_version(version, "12.1YH")) {
 report_extra = '\nUpdate to 12.2(13)T5 or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(10d)", "12.2(12e)", "12.2(13c)", "12.2(16a)", "12.2(17)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(15)B1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(15)BC1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2BW")) {
 report_extra = '\nUpdate to 12.2(15)T12 or later\n'; flag++;
}
# Affected: 12.2BX
if (check_release(version: version,
                  patched: make_list("12.2(16)BX") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2BY")) {
 report_extra = '\nUpdate to 12.2(15)B1 or later\n'; flag++;
}
if (deprecated_version(version, "12.2BZ")) {
 report_extra = '\nUpdate to 12.2(16)BX or later\n'; flag++;
}
# Affected: 12.2CX
if (check_release(version: version,
                  patched: make_list("12.2(15)CX") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(12)DA6") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2DD")) {
 report_extra = '\nUpdate to 12.2(15)B1 or later\n'; flag++;
}
if (deprecated_version(version, "12.2DX")) {
 report_extra = '\nUpdate to 12.2(15)B1 or later\n'; flag++;
}
# Affected: 12.2EW
if (check_release(version: version,
                  patched: make_list("12.2(18)EW") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2JA
if (check_release(version: version,
                  patched: make_list("12.2(13)JA") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(14)S2", "12.2(18)S") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SE
if (check_release(version: version,
                  patched: make_list("12.2(18)SE") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SU
if (check_release(version: version,
                  patched: make_list("12.2(14)SU") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SV
if (check_release(version: version,
                  patched: make_list("12.2(18)SV") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SW
if (check_release(version: version,
                  patched: make_list("12.2(18)SW") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(14)SX2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# only 12.2SXA affected. check_release() doesn't account for this - it treats all 12.2SXn
# releases (where 'n' is an uppercase letter) as 12.2SX releases
if ("SXA" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(17b)SXA") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# only 12.2SXB affected. check_release() doesn't account for this - it treats all 12.2SXn
# releases (where 'n' is an uppercase letter) as 12.2SX releases
if ("SXB" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(17d)SXB") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SY
if (check_release(version: version,
                  patched: make_list("12.2(14)SY") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(14)SZ2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(4)T6", "12.2(8)T10", "12.2(11)T9", "12.2(13)T5", "12.2(15)T4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2XA")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(2)XB16") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2XD")) {
 report_extra = '\nUpdate to 12.2(8)T10 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XE")) {
 report_extra = '\nUpdate to 12.2(8)T10 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XG")) {
 report_extra = '\nUpdate to 12.2(8)T10 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XH")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XI")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XJ")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XK")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XL")) {
 report_extra = '\nUpdate to 12.2(15)T4 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XM")) {
 report_extra = '\nUpdate to 12.2(15)T4 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XN")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XQ")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XS")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XT")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XU")) {
 report_extra = '\nUpdate to 12.2(15)T12 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XW")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YA")) {
 report_extra = '\nUpdate to 12.2(15)T4 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YB")) {
 report_extra = '\nUpdate to 12.2(15)T4 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YC")) {
 report_extra = '\nUpdate to 12.2(11)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YD")) {
 report_extra = '\nUpdate to 12.2(8)YY or later\n'; flag++;
}
if (deprecated_version(version, "12.2YE")) {
 report_extra = '\nUpdate to 12.2(18)S or later\n'; flag++;
}
if (deprecated_version(version, "12.2YF")) {
 report_extra = '\nUpdate to 12.2(15)T4 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YG")) {
 report_extra = '\nUpdate to 12.2(13)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YH")) {
 report_extra = '\nUpdate to 12.2(15)T4 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YJ")) {
 report_extra = '\nUpdate to 12.2(15)T4 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YL")) {
 report_extra = '\nUpdate to 12.3(2)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YM")) {
 report_extra = '\nUpdate to 12.3(2)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YN")) {
 report_extra = '\nUpdate to 12.3(2)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YO")) {
 report_extra = '\nUpdate to 12.2(14)SY or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(11)YP1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2YQ")) {
 report_extra = '\nUpdate to 12.3(4)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YR")) {
 report_extra = '\nUpdate to 12.3(4)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YS")) {
 report_extra = '\nUpdate to 12.3T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YT")) {
 report_extra = '\nUpdate to 12.2(15)T4 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YU")) {
 report_extra = '\nUpdate to 12.3(4)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YV")) {
 report_extra = '\nUpdate to 12.3(4)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YW")) {
 report_extra = '\nUpdate to 12.3(2)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YX")) {
 report_extra = '\nUpdate to 12.2(14)SU or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(8)YY3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2YZ")) {
 report_extra = '\nUpdate to 12.2(14)SZ or later\n'; flag++;
}
if (check_release(version: version,
                  patched: make_list("12.2(14)ZA2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZB")) {
 report_extra = '\nUpdate to 12.3T or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZC")) {
 report_extra = '\nUpdate to 12.3T or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZE")) {
 report_extra = '\nUpdate to 12.3 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZF")) {
 report_extra = '\nUpdate to 12.3(4)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZG")) {
 report_extra = '\nUpdate to 12.3(4)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZH")) {
 report_extra = '\nUpdate to 12.3(4)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZI")) {
 report_extra = '\nUpdate to 12.2(18)S or later\n'; flag++;
}
# Affected: 12.2ZK
if (check_release(version: version,
                  patched: make_list("12.2(15)ZK") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2ZL
if (check_release(version: version,
                  patched: make_list("12.2(15)ZL") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZN")) {
 report_extra = '\nUpdate to 12.3(2)T or later\n'; flag++;
}
# Affected: 12.2ZO
if (check_release(version: version,
                  patched: make_list("12.2(15)ZO") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2ZP
if (check_release(version: version,
                  patched: make_list("12.2(13)ZP") )) {
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
      if (preg(pattern:"router\s+bgp\s+", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_warning(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
