#TRUSTED 7f156c713e8324172ab71a2be2461466d14135ac628009dcf033b4fa208219f0cf1207542008af3d3d628f8e93caf41364a1cd97930b6eaaf0795d107e28ce0ac68f0f859d747870e9bb2087b3634d2bdf97ada93ec2aa1c3f90a6e6c0411f826acba8a52da143562c6d5118aa09ae08bdfc1ebb1d82607ab0a3e053a6eefd140b2aa6cb3b4de4b48a44516f59deca0ef7110fc0707b8799fb7b2a1c207a36b329409213251a7ce47a2e68d19672c4aea11a725c7c0b666a8c9bcc162c2b9d79c6e6dd8640b1720889b905a223db2190424e28620f86527859ff3188d60b947e310244d0a25ae75f59f38ffafe7f46ab0ed8885849d4ec5768e377a04e4b10684b22fe8f251ecd0d3ea6d215fb598037ff9fd5b2f33b29a87d5c5fe07283e699abaa811367701f609506cdafc11d10d71931618e8bf79d4e40a72ef7efd529ff38584b23f8c408080154cabd6929f94b08aabf451f11e2ea5dc7b52aaff05b108f0d85431477b61ead31ede4c92ba684be38114fa46cba8003e7f02afc939b32d1bac72db4474f796ae3792c0bf7e640f4e5ce99a5f8691a53bb8517c541748d281a72375093a21cd36fda457ab68b22b75b3ce8b3a78b75d65cbc33e3d1788467c218b3cf43c4bad3b4d94d2e448f897acdf0afce0458117a62c5bd9ca42b453fd6b02e2ed1a393003dd69d1eb1cbb2577b3791b4bf389b8daa1acf9f1e7a1a
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a008009fafa.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48967);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2002-1024");
 script_bugtraq_id(5114);
 script_xref(name:"CERT", value:"290140");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv85279");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw29965");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw33027");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw59394");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx59197");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20020627-ssh-scan");
 script_name(english:"Scanning for SSH Can Cause a Crash - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'While fixing vulnerabilities mentioned in the Cisco Security Advisory
cisco-sa-20010627-ssh, a new vulnerability was introduced in some
products. When an attacker tries to exploit the vulnerability VU#945216
(described in the CERT/CC Vulnerability Note at
http://www.kb.cert.org/vuls/id/945216) the SSH module will consume too
much of the processor\'s time, effectively causing a DoS. In some cases
the device will reboot. In order to be exposed SSH must be enabled on
the device.
It is possible to mitigate this vulnerability by preventing, or having
control over, the SSH traffic.');
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020627-ssh-scan
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fab8dcf4");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a008009fafa.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?b9451893");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20020627-ssh-scan.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/27");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/06/27");
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
report_extra = "";
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(17)S4", "12.0(20.4)S", "12.0(21)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0SP
if (check_release(version: version,
                  patched: make_list("12.0(20)SP2", "12.0(20.4)SP") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(17)ST5", "12.0(20.3)ST2"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0XB
if (deprecated_version(version, "12.0XB")) {
 report_extra = '\nUpdate to 12.1(1)T or later\n'; flag++;
}
# Affected: 12.0XM
if (deprecated_version(version, "12.0XM")) {
 report_extra = '\nUpdate to 12.1(3)T or later\n'; flag++;
}
# Affected: 12.0XV
if (deprecated_version(version, "12.0XV")) {
 report_extra = '\nUpdate to 12.1(2)T or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(8b)E8", "12.1(10.5)E", "12.1(11b)E"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(10.5)EC", "12.1(12c)EC"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1(1)EX
if (version == '12.1(1)EX') {
 report_extra = '\nUpdate to 12.1(3)T or later\n'; flag++;
}
# Affected: 12.1(5c)EX
if (version == '12.1(5c)EX') {
 report_extra = '\nUpdate to 12.1(6)EX or later\n'; flag++;
}
# Affected: 12.1(8a)EX
if (version == '12.1(8a)EX') {
 report_extra = '\nUpdate to 12.1(11)E or later\n'; flag++;
}
# Affected: 12.1(9)EX
if (version == '12.1(9)EX') {
 report_extra = '\nUpdate to 12.1(10)EX or later\n'; flag++;
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 report_extra = '\nUpdate to 12.2(7) or later\n'; flag++;
}
# Affected: 12.1XB
if (deprecated_version(version, "12.1XB")) {
 report_extra = '\nUpdate to 12.1(5)YB or later\n'; flag++;
}
# Affected: 12.1XC
if (deprecated_version(version, "12.1XC")) {
 report_extra = '\nUpdate to 12.2(7) or later\n'; flag++;
}
# Affected: 12.1XF
if (check_release(version: version,
                  patched: make_list("12.1(2)XF6"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XG
if (check_release(version: version,
                  patched: make_list("12.1(3)XG7"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XH
if (deprecated_version(version, "12.1XH")) {
 report_extra = '\nUpdate to 12.2(7) or later\n'; flag++;
}
# Affected: 12.1XI
if (deprecated_version(version, "12.1XI")) {
 report_extra = '\nUpdate to 12.2(7) or later\n'; flag++;
}
# Affected: 12.1XJ
if (deprecated_version(version, "12.1XJ")) {
 report_extra = '\nUpdate to 12.2(2)T or later\n'; flag++;
}
# Affected: 12.1XL
if (deprecated_version(version, "12.1XL")) {
 report_extra = '\nUpdate to 12.2(7) or later\n'; flag++;
}
# Affected: 12.1XM
if (check_release(version: version,
                  patched: make_list("12.1(5)XM7"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XP
if (deprecated_version(version, "12.1XP")) {
 report_extra = '\nUpdate to 12.2(2)T or later\n'; flag++;
}
# Affected: 12.1XQ
if (deprecated_version(version, "12.1XQ")) {
 report_extra = '\nUpdate to 12.2(2)XB or later\n'; flag++;
}
# Affected: 12.1XT
if (deprecated_version(version, "12.1XT")) {
 report_extra = '\nUpdate to 12.2(2)T or later\n'; flag++;
}
# Affected: 12.1XU
if (deprecated_version(version, "12.1XU")) {
 report_extra = '\nUpdate to 12.2(2)T or later\n'; flag++;
}
# Affected: 12.1YB
if (check_release(version: version,
                  patched: make_list("12.1(5)YB6"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YC
if (check_release(version: version,
                  patched: make_list("12.1(5)YC3"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YD
if (deprecated_version(version, "12.1YD")) {
 report_extra = '\nUpdate to 12.2(8)T or later\n'; flag++;
}
# Affected: 12.1YE
if (deprecated_version(version, "12.1YE")) {
 report_extra = '\nUpdate to 12.1(5)YI or later\n'; flag++;
}
# Affected: 12.1YF
if (deprecated_version(version, "12.1YF")) {
 report_extra = '\nUpdate to 12.2(2)XN or later\n'; flag++;
}
# Affected: 12.1YI
if (deprecated_version(version, "12.1YI")) {
 report_extra = '\nUpdate to 12.2(2)YC or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(6b)", "12.2(7.4)", "12.2(7)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2B
if (check_release(version: version,
                  patched: make_list("12.2(4)B3", "12.2(7.6)B") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2BC
if (check_release(version: version,
                  patched: make_list("12.2(8)BC1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2DA
if (check_release(version: version,
                  patched: make_list("12.2(6.8a)DA", "12.2(7)DA"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2DD
if (deprecated_version(version, "12.2DD")) {
 report_extra = '\nUpdate to 12.2(4)B1 or later\n'; flag++;
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(7.4)S") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(7.4)T", "12.2(8)T"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XA
if (deprecated_version(version, "12.2XA")) {
 report_extra = '\nUpdate to 12.2(4)T or later\n'; flag++;
}
# Affected: 12.2XB
if (check_release(version: version,
                  patched: make_list("12.2(2)XB4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XD
if (check_release(version: version,
                  patched: make_list("12.2(1)XD4"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XE
if (check_release(version: version,
                  patched: make_list("12.2(1)XE3"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XF
if (deprecated_version(version, "12.2XF")) {
 report_extra = '\nUpdate to 12.2(4)BC1 or later\n'; flag++;
}
# Affected: 12.2XG
if (deprecated_version(version, "12.2XG")) {
 report_extra = '\nUpdate to 12.2(8)T or later\n'; flag++;
}
# Affected: 12.2XH
if (check_release(version: version,
                  patched: make_list("12.2(2)XH3"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XI
if (check_release(version: version,
                  patched: make_list("12.2(2)XI2"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XJ
if (deprecated_version(version, "12.2XJ")) {
 report_extra = '\nUpdate to 12.2(4)YB or later\n'; flag++;
}
# Affected: 12.2XK
if (check_release(version: version,
                  patched: make_list("12.2(2)XK3"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XL
if (check_release(version: version,
                  patched: make_list("12.2(4)XL5"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XM
if (check_release(version: version,
                  patched: make_list("12.2(4)XM4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XN
if (deprecated_version(version, "12.2XN")) {
 report_extra = '\nNo fix is available for 12.2XN releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2XQ
if (deprecated_version(version, "12.2XQ")) {
 report_extra = '\nUpdate to 12.2(4)YB or later\n'; flag++;
}
# Affected: 12.2XR
if (check_release(version: version,
                  patched: make_list("12.2(4)XR") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XS
if (deprecated_version(version, "12.2XS")) {
 report_extra = '\nUpdate to 12.2(6) or later\n'; flag++;
}
# Affected: 12.2XT
if (deprecated_version(version, "12.2XT")) {
 report_extra = '\nUpdate to 12.2(8)T or later\n'; flag++;
}
# Affected: 12.2XW
if (deprecated_version(version, "12.2XW")) {
 report_extra = '\nUpdate to 12.2(4)YB or later\n'; flag++;
}
# Affected: 12.2YA
if (check_release(version: version,
                  patched: make_list("12.2(4)YA2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2YB
if (deprecated_version(version, "12.2YB")) {
 report_extra = '\nNo fix is available for 12.2YB releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2YC
if (deprecated_version(version, "12.2YC")) {
 report_extra = '\nUpdate to 12.2(13)T or later\n'; flag++;
}
# Affected: 12.2YD
if (deprecated_version(version, "12.2YD")) {
 report_extra = '\nUpdate to 12.2(8)B or later\n'; flag++;
}
# Affected: 12.2YF
if (deprecated_version(version, "12.2YF")) {
 report_extra = '\nNo fix is available for 12.2YF releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2YG
if (check_release(version: version,
                  patched: make_list("12.2(4)YG"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2YH
if (check_release(version: version,
                  patched: make_list("12.2(4)YH"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ssh", "show ip ssh");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SSH\s+Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

