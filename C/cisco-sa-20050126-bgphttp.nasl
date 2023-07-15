#TRUSTED 40811832c6e5f4e993676412163247b4e5785171831c886e81ba1270f3e6dbc463f01d27be6e613a7ad36bfab39e65ec151fe84e6fcd5280a7d72ee5f58a3031b08f47d368552c0c02548cd96a02a9da863edb9e535d1f510ae38a115f273e93afe75ad650dfe923640306f23027e6ed06357f0945749438386a73473315bb9c5e31e4ec546eb8fc0d7f39d591b60da95f9872a0a666c7cda4e089f74376ce785e92e53a4574234662dafdb4642c75acff50e6caaa224a5c8b8857751a7bea857149e5cb898e1bfb174a7f5381749519cc86f56a25a632af90ccf19c3c7370f7ca1e0bfcb643f7ffef65db2ff621fa8a45c3c2709531cee038e91df9e698c604100fafb849cfd6df4945355041dbf9850a1a2a5e329b13cfb98dbfa55057ace36aecf5b60159443343f1edb2b0080f2f55ce5d3fdaec5a015a7fbab1f80b58d6e3ca904a6f6d872e8c5177194dc2f058ae4f668648bd510f552494419e17b287ae69c2285f9a0232119c78e6edfc5673f7fc8ec5e6bfd5c62b302d5952f37e2283bb36e97132caf65dba848d6ea3a312ad5bf6097a8520142aba4c76beea3a7cb20dd4172d54450941006bd67bd6e012fcedcde421ef45b8ccf713ed543291af630b4b883d0cd811639f28b525acf77752332fc09e8c6b5d444bfbcb3f2fae2ef692d295fde756443f67c6b3aefe86621e3433d29698e71272ff0c8b4881f882
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00803be7d9.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48980);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2005-0196");
 script_bugtraq_id(12370);
 script_xref(name:"CERT", value:"689326");
 script_name(english:"Cisco IOS Misformed BGP Packet Causes Reload - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'A Cisco device running IOS Border Gateway Protocol (BGP) is vulnerable
to a Denial of Service (DoS) attack from a malformed BGP packet. Only
devices with either the command bgp log-neighbor-changes configured or
the command snmp-server enable traps bgp are vulnerable. The BGP
protocol is not enabled by default, and must be configured in order to
accept traffic from an explicitly defined peer. Unless the malicious
traffic appears to be sourced from a configured, trusted peer, it would
be difficult to inject a malformed packet.
Cisco has made free software available to address this problem.'
 );
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20050126-bgp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17e5d4c7");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00803be7d9.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?ff839049");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20050126-bgp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/26");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/01/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx23494");
 script_xref(name:"CISCO-BUG-ID", value:"CSCee67450");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20050126-bgp");
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

# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(28b)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0DA")) {
 report_extra = '\nNo fix is planned for 12.0DA releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.0DB")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.0DC")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(25)S5", "12.0(26)S2d", "12.0(26)S5", "12.0(27)S2d", "12.0(27)S4", "12.0(28)S1", "12.0(29)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0SC")) {
 report_extra = '\nNo fix is planned for 12.0SC releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.0SP")) {
 report_extra = '\nUpdate to 12.0(29)S or later\n'; flag++;
}
if (deprecated_version(version, "12.0ST")) {
 report_extra = '\nUpdate to 12.0(26)S5 or later\n'; flag++;
}
# Affected: 12.OSV
if (check_release(version: version,
                  patched: make_list("12.0(27)SV4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0SX")) {
 report_extra = '\nNo fix is planned for 12.0SX releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.0SY")) {
 report_extra = '\nUpdate to 12.0(26)S5 or later\n'; flag++;
}
if (deprecated_version(version, "12.0SZ")) {
 report_extra = '\nUpdate to 12.0(26)S5 or later\n'; flag++;
}
# Affected: 12.0W5
if (
 "W5" >< version && # avoid flagging versions like W4
 check_release(version: version, patched:make_list("12.0(28)W5(31)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0WC")) {
 report_extra = '\nNo fix is planned for 12.0WC releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.0WT")) {
 report_extra = '\nNo fix is planned for 12.0WT releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.0WX")) {
 report_extra = '\nNo fix is planned for 12.0WX releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.0XA")) {
 report_extra = '\nUpdate to 12.1(26) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XB")) {
 report_extra = '\nUpdate to 12.0(1)T or later\n'; flag++;
}
if (deprecated_version(version, "12.0XC")) {
 report_extra = '\nUpdate to 12.1(26) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XD")) {
 report_extra = '\nUpdate to 12.1(26) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XE")) {
 report_extra = '\nUpdate to 12.1(26)E or later\n'; flag++;
}
if (deprecated_version(version, "12.0XF")) {
 report_extra = '\nNo fix is planned for 12.0XF releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.0XG")) {
 report_extra = '\nUpdate to 12.1(26) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XH")) {
 report_extra = '\nUpdate to 12.1(26) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XI")) {
 report_extra = '\nUpdate to 12.1(26) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XJ")) {
 report_extra = '\nUpdate to 12.1(26) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XK")) {
 report_extra = '\nUpdate to 12.2(27) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XL")) {
 report_extra = '\nUpdate to 12.2(27) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XM")) {
 report_extra = '\nUpdate to 12.1(26) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XN")) {
 report_extra = '\nUpdate to 12.1(26) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XP")) {
 report_extra = '\nNo fix is planned for 12.0XP releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.0XQ")) {
 report_extra = '\nUpdate to 12.1(26) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XR")) {
 report_extra = '\nUpdate to 12.2(27)or later\n'; flag++;
}
if (deprecated_version(version, "12.0XS")) {
 report_extra = '\nUpdate to 12.1(26)E or later\n'; flag++;
}
if (deprecated_version(version, "12.0XT")) {
 report_extra = '\nNo fix is planned for 12.0XT releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.0XU")) {
 report_extra = '\nNo fix is planned for 12.0XU releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.0XV")) {
 report_extra = '\nUpdate to 12.1(26) or later\n'; flag++;
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(26)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.1AA")) {
 report_extra = '\nUpdate to 12.2(27) or later\n'; flag++;
}
# Affected: 12.1AX
if (check_release(version: version,
                  patched: make_list("12.1(14)AX3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.1AY")) {
 report_extra = '\nUpdate to 12.1(22)EA2 or later\n'; flag++;
}
if (deprecated_version(version, "12.1AZ")) {
 report_extra = '\nUpdate to 12.1(22)EA2 or later\n'; flag++;
}
if (deprecated_version(version, "12.1DA")) {
 report_extra = '\nNo fix is planned for 12.1DA releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.1DB")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.1DC")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(22)E3", "12.1(23)E2", "12.1(26)E"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EA
if (check_release(version: version,
                  patched: make_list("12.1(22)EA2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.1EC")) {
 report_extra = '\nNo fix is planned for 12.1EC releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.1EO")) {
 report_extra = '\nNo fix is planned for 12.1EO releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.1EV")) {
 report_extra = '\nUpdate to 12.2(25)S or later\n'; flag++;
}
if (deprecated_version(version, "12.1EW")) {
 report_extra = '\nUpdate to 12.2(18)EW2 or later\n'; flag++;
}
if (deprecated_version(version, "12.1EX")) {
 report_extra = '\nUpdate to 12.1(26)E or later\n'; flag++;
}
if (deprecated_version(version, "12.1EY")) {
 report_extra = '\nUpdate to 12.1(26)E or later\n'; flag++;
}
if (deprecated_version(version, "12.1T")) {
 report_extra = '\nUpdate to 12.2(27) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XA")) {
 report_extra = '\nUpdate to 12.2(27) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XB")) {
 report_extra = '\nUpdate to 12.2(27) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XC")) {
 report_extra = '\nUpdate to 12.2(27) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XD")) {
 report_extra = '\nUpdate to 12.2(27) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XE")) {
 report_extra = '\nUpdate to 12.1(26)E or later\n'; flag++;
}
if (deprecated_version(version, "12.1XF")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XG")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XH")) {
 report_extra = '\nUpdate to 12.2(27) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XI")) {
 report_extra = '\nUpdate to 12.2(27) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XJ")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XL")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XM")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XP")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XQ")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XR")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XT")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XU")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1XV")) {
 report_extra = '\nNo fix is planned for 12.1XV releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.1YA")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1YB")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1YC")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1YD")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1YE")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1YF")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1YH")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.1YI")) {
 report_extra = '\nUpdate to 12.2(2)YC or later\n'; flag++;
}
if (deprecated_version(version, "12.1YJ")) {
 report_extra = '\nUpdate to 12.1(22)EA2 or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(27)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2B")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2BC")) {
 report_extra = '\nNo fix is planned for 12.2BC releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.2BW")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2BX")) {
 report_extra = '\nUpdate to 12.3(7)XI3 or later\n'; flag++;
}
if (deprecated_version(version, "12.2BY")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2BZ")) {
 report_extra = '\nUpdate to 12.3(7)XI3 or later\n'; flag++;
}
if (deprecated_version(version, "12.2CZ")) {
 report_extra = '\nNo fix is planned for 12.2CZ releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.2DA")) {
 report_extra = '\nNo fix is planned for 12.2DA releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.2DD")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2DX")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
# Affected: 12.2EW
if (check_release(version: version,
                  patched: make_list("12.2(18)EW2", "12.2(25)EW"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2JK
if (check_release(version: version,
                  patched: make_list("12.2(15)JK2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2MB")) {
 report_extra = '\nUpdate to 12.2(25)SW or later\n'; flag++;
}
if (deprecated_version(version, "12.2MC")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2MX")) {
 report_extra = '\nUpdate to 12.3(8)T5 or later\n'; flag++;
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(14)S13", "12.2(18)S8", "12.2(20)S7", "12.2(25)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SE
if (check_release(version: version,
                  patched: make_list("12.2(20)SE3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SU
if (check_release(version: version,
                  patched: make_list("12.2(14)SU2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2SW")) {
 report_extra = '\nUpdate to 12.2(25)SW or later\n'; flag++;
}
# Affected: 12.2SXB
# this should cover 12.2SX and 12.2SX as well - check_release() does not treat any
# uppercase letters after 'SX' as part of the train ID
if (check_release(version: version,
                  patched: make_list("12.2(17d)SXB5") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SXD
if ("SXD" >< version &&
    check_release(version: version,
                  patched: make_list("12.2(18)SXD2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2SY")) {
 report_extra = '\nUpdate to 12.2(17d)SXB5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2SZ")) {
 report_extra = '\nUpdate to 12.2(25)S or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(15)T15") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2XA")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XB")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XC")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XD")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XE")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XF")) {
 report_extra = '\nNo fix is planned for 12.2XF releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.2XG")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XH")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XI")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XJ")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XK")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XL")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XM")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XN")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XQ")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XS")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XT")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XU")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XW")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XZ")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
# Affected: 12.2YA
if (check_release(version: version,
                  patched: make_list("12.2(4)YA8") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2YB")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2YC")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2YE")) {
 report_extra = '\nUpdate to 12.2(25)S or later\n'; flag++;
}
if (deprecated_version(version, "12.2YF")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2YG")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2YH")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2YJ")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2YK")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YL")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YM")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YN")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YO")) {
 report_extra = '\nUpdate to 12.2(17d)SXB5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YP")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2YQ")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YR")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YS")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YT")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2YU")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YV")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YW")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YX")) {
 report_extra = '\nUpdate to 12.2(14)SU2 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YY")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
if (deprecated_version(version, "12.2YZ")) {
 report_extra = '\nUpdate to 12.2(25)S or later\n'; flag++;
}
# Affected: 12.2ZA
if (deprecated_version(version, "12.2ZA")) {
 report_extra = '\nUpdate to 12.2(17d)SXB5 / 12.2(18)SXD2 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZB")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZC")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZD")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZE")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZF")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZG")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZH")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZI")) {
 report_extra = '\nUpdate to 12.2(25)S or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZJ")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
# Affected: 12.2ZK
if (check_release(version: version,
                  patched: make_list("12.2(15)ZK6") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZL")) {
 report_extra = '\nUpdate to 12.3(7)T7 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZN")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZO")) {
 report_extra = '\nUpdate to 12.3(12) or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZP")) {
 report_extra = '\nNo fix is planned for 12.2ZP releases. Upgrade to a supported release\n'; flag++;
}
# Affected: 12.3
if (check_release(version: version,
                  patched: make_list("12.3(6d)", "12.3(9c)", "12.3(10a)", "12.3(12)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3B
if (check_release(version: version,
                  patched: make_list("12.3(5a)B3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3BC
if (check_release(version: version,
                  patched: make_list("12.3(9a)BC1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.3BW")) {
 report_extra = '\nUpdate to 12.3(7)T7 or later\n'; flag++;
}
# Affected: 12.3T
if (check_release(version: version,
                  patched: make_list("12.3(4)T11", "12.3(7)T7", "12.3(8)T5", "12.3(11)T"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.3XA")) {
 report_extra = '\nUpdate to 12.3(7)T7 or later\n'; flag++;
}
if (deprecated_version(version, "12.3XB")) {
 report_extra = '\nUpdate to 12.3(8)T5 or later\n'; flag++;
}
# Affected: 12.3XC
if (check_release(version: version,
                  patched: make_list("12.3(2)XC3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3XD
if (check_release(version: version,
                  patched: make_list("12.3(4)XD4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3XE
if (check_release(version: version,
                  patched: make_list("12.3(2)XE1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.3XF")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
if (deprecated_version(version, "12.3XG")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
if (deprecated_version(version, "12.3XH")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
# Affected: 12.3XI
if (check_release(version: version,
                  patched: make_list("12.3(7)XI3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.3XJ")) {
 report_extra = '\nNo fix is planned for 12.3XJ releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.3XK")) {
 report_extra = '\nNo fix is planned for 12.3XK releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.3XL")) {
 report_extra = '\nNo fix is planned for 12.3XL releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.3XN")) {
 report_extra = '\nNo fix is planned for 12.3XN releases. Upgrade to a supported release\n'; flag++;
}
# Affected: 12.3XQ
if (check_release(version: version,
                  patched: make_list("12.3(4)XQ1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.3XR")) {
 report_extra = '\nNo fix is planned for 12.3XR releases. Upgrade to a supported release\n'; flag++;
}
# Affected: 12.3XS
if (check_release(version: version,
                  patched: make_list("12.3(7)XS2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3XU
if (check_release(version: version,
                  patched: make_list("12.3(8)XU4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.3XV")) {
 report_extra = '\nUpdate to 12.3(11)T or later\n'; flag++;
}
# Affected: 12.3XX
if (check_release(version: version,
                  patched: make_list("12.3(8)XX1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3YA
if (check_release(version: version,
                  patched: make_list("12.3(8)YA1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.3YC")) {
 report_extra = '\nNo fix is planned for 12.3YC releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.3YD")) {
 report_extra = '\nNo fix is planned for 12.3YD releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.3YE")) {
 report_extra = '\nUpdate to 12.3(4)T11 or later\n'; flag++;
}
if (deprecated_version(version, "12.3YF")) {
 report_extra = '\nNo fix is planned for 12.3YF releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.3YH")) {
 report_extra = '\nNo fix is planned for 12.3YH releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.3YJ")) {
 report_extra = '\nNo fix is planned for 12.3YJ releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.3YL")) {
 report_extra = '\nNo fix is planned for 12.3YL releases. Upgrade to a supported release\n'; flag++;
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
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

