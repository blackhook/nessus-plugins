#TRUSTED 4de9d7e39c170615f9c33e9ef7dbbf98ea7ec4e640a8ad2815a66a15f3712f4398a0b6dac19d5b7e79a0a9a7ec82a56e0c7eb952ac48c0a3461986cee61d63dafbd54c2625d797bbaf82ed49d532817ae151389dce7ccedaba29497f8bd5c5a369f30189085c9ab03fefdd7c79dabd5fcc592735930461a45fe7ed24a664dffb01eed327cd864e2748a6b667d75434340024898e1f619e8649799d4cf4c4fc5f037974e44da109255b7c5e111e3d995fd653d30113dbe80d59f4c8e0fda03b4b866709e2784e03d9b458dd8d84f7fd027a14ff519aa7521e08bbf7193551f091f715416a45a153c411ff3e26796f6370269a0d573a19f3288411b4921fbb398fc871de7d8238b7aa5cf66e418b1fd31123d1d09e164f9dfc0b4a1efacf9cf05830d83451fed262941bc91b5b9f77b0f05484dc5e6f51174f096eef78048903826e65f3addb37137ce70317a46473e0cb9b88f96e7ca8d6aa5f5670e01a8a67cee7447e930bd83c2bb8ffd3f61a31c9ee6e56d22dfccd389552f0ab4b864f112f9737240d4c25e0a1525d34fb46a246c0c0da29525a6d6ccf3afb2c1e20aa8b25ef3e41c1cb590482306e63f0262473841f1b895282e88bee115438fc1a680d6cc2a7905e61d3414d19aef1d4179bd645f5f0987d8a20098b006f44fb0763788c87d2ee21ca2ac702cfcaa0c28f68ff46bb7831750e16bd39335560be0e127148
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a008017ba10.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(55385);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2003-0305");
 script_bugtraq_id(7607);
 script_name(english:"Cisco IOS Software Processing of SAA Packets - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'The Service Assurance Agent (SAA) is the new name for the Response Time
Reporter (RTR) feature.
The router is vulnerable only if the RTR responder is enabled. When the
router receives a malformed RTR packet, it will crash. RTR is disabled
by default.
There is no workaround short of disabling the RTR responder. It is
possible to mitigate the vulnerability by applying the access control
list (ACL) on the router.
');
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20030515-saa
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef55d88d");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a008017ba10.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?0bb3e4d4");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20030515-saa.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/05/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/22");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx17916");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx61997");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20030515-saa");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2011-2018 Tenable Network Security, Inc.");
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
                  patched: make_list("12.0(21)S3", "12.0(21.03)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0SC
if (deprecated_version(version, "12.0SC")) {
 report_extra = '\nNo fix is available for 12.0SC releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0SL
if (deprecated_version(version, "12.0SL")) {
 report_extra = '\nNo fix is available for 12.0SL releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0SP
if (check_release(version: version,
                  patched: make_list("12.0(20)SP3", "12.0(20.04)SP2"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(19)ST5", "12.0(21)ST2"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0SX
if (deprecated_version(version, "12.0SX")) {
 report_extra = '\nNo fix is available for 12.0SX releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0SY
if (check_release(version: version,
                  patched: make_list("12.0(21.03)SY", "12.0(22)SY"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0WC
if (check_release(version: version,
                  patched: make_list("12.0(5)WCa"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0XE")) {
 report_extra = '\nNo fix is available for 12.0XE releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(18)", "12.1(18.1)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(12.5)E", "12.1(13)E"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EA
if (check_release(version: version,
                  patched: make_list("12.1(8)EA1c"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(12c)EC"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EW
if (check_release(version: version,
                  patched: make_list("12.1(11b)EW", "12.1(11b)EW(0.46)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EX
if (check_release(version: version,
                  patched: make_list("12.1(11b)EX"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XF
if (deprecated_version(version, "12.1XF")) {
 report_extra = '\nUpdate to 12.1(5)T or later\n'; flag++;
}
# Affected: 12.1XG
if (deprecated_version(version, "12.1XG")) {
 report_extra = '\nUpdate to 12.1(1)T or later\n'; flag++;
}
# Affected: 12.1YB
if (deprecated_version(version, "12.1YB")) {
 report_extra = '\nUpdate to 12.1(2)T or later\n'; flag++;
}
# Affected: 12.1YC
if (deprecated_version(version, "12.1YC")) {
 report_extra = '\nUpdate to 12.1(4)T or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(10)", "12.2(10.4)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(4)B
if (version == "12.2(4)B") {
 report_extra = '\nUpdate to 12.2(13.3)B or later\n'; flag++;
}
# Affected: 12.2BC
if (deprecated_version(version, "12.2BC")) {
 report_extra = '\nNo fix is available for 12.2BC releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2BY
if (deprecated_version(version, "12.2BY")) {
 report_extra = '\nUpdate to 12.2(13.3)B or later\n'; flag++;
}
# Affected: 12.2BZ
if (check_release(version: version,
                  patched: make_list("12.2(15)BZ"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2DA
if (check_release(version: version,
                  patched: make_list("12.2(11.4)DA", "12.2(12)DA"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2MB
if (check_release(version: version,
                  patched: make_list("12.2(4)MB5"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(11.1)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XC
if (check_release(version: version,
                  patched: make_list("12.2(1a)XC5"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XD
if (deprecated_version(version, "12.2XD")) {
 report_extra = '\nUpdate to 12.2(8)YN or later\n'; flag++;
}
# Affected: 12.2XE
if (deprecated_version(version, "12.2XE")) {
 report_extra = '\nUpdate to 12.2(8)T or later\n'; flag++;
}
# Affected: 12.2XH
if (deprecated_version(version, "12.2XH")) {
 report_extra = '\nUpdate to 12.2(8)T or later\n'; flag++;
}
# Affected: 12.2XI
if (deprecated_version(version, "12.2XI")) {
 report_extra = '\nUpdate to 12.2(12)T or later\n'; flag++;
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
if (deprecated_version(version, "12.2XM")) {
 report_extra = '\nUpdate to 12.2(8)YB or later\n'; flag++;
}
# Affected: 12.2YA
if (check_release(version: version,
                  patched: make_list("12.2(4)YA3"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2YB
if (check_release(version: version,
                  patched: make_list("12.2(8)YB"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2YC
if (check_release(version: version,
                  patched: make_list("12.2(4)YC4"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
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
    buf = cisco_command_kb_item("Host/Cisco/Config/show rtr responder", "show rtr responder");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"RTR\s+Responder\s+is:\s+Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
