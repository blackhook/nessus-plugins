#TRUSTED 134089c79ffa0d35d71016e7647f060cad6858c0642f2f316a02eb9c4220913f85a199d77553bad67b55ee5eeccf369cc49c4b7cbd84eb8481286cee2b9e2a98fdad77cf62756c0816c75e1e78878ebdb38741da1a65219159a05c42987892b4acca6f4f163b56368ed716865ec7b36a3ec40056d0078bf055c9b1ae8b02083a8776b413da4b6559aa1d9dabcd88985247471ad4a27a2865d50881097a6586348a8ed4972bcbabd060e5590571f7864ab376607e5c1e9add0705bed139e32412ab00b0d2db8b9d311c2ad8a7e3366fb00139ebf3a0bd6a765d9c6b2182eeb8758b53686ea5a3b2e26366f75d0d3bcdf215d0f92d9219487047bae27b223b53c1b2db7e92e0570cb7139b8908fa5d964b213f80c3fc699ecd3f90e2479be2e6cb77a22447c2ff55a06afaf9e180ad3b7dab84d56c0be19fb2b684d37a2417e736bac08265c699eb4667093daabe6259573d65cae39eb9fa8f24dfe70fac7fe5ddf170ffe8e39bce0736bf339ce8618a3561ef70f1c2bf242c77224e03c85e8e4007965cd99cccf6325de576ebd112107ac23f65ed06495d0cc11a2e0d54b36cab0691078711a80163dda147c9630b5052cb519b788188fdce6db328b1a70c69fc6a70894b2d9606698109365a843b4123edd52370aebfb5cebec6803e7d220266c09cb58bf5d6625ff3a0606e28c8e36f3ff3a04eeb12252d4844c23e3325fb34
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00800b168e.shtml

include("compat.inc");

if (description)
{
 script_id(48957);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_cve_id("CVE-2001-0572");
 script_xref(name:"CERT", value:"596827");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt55357");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt57231");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt72996");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt73353");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt96253");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu37371");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv34668");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv34676");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv34679");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20010627-ssh");

 script_name(english:"Multiple SSH Vulnerabilities - Cisco Systems");
 script_summary(english:"Checks the IOS version.");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'Four different Cisco product lines are susceptible to multiple
vulnerabilities discovered in the Secure Shell (SSH) protocol version
1.5. These issues have been addressed, and fixes have been integrated
into the Cisco products that support this protocol.
By exploiting the weakness in the SSH protocol, it is possible to
insert arbitrary commands into an established SSH session, collect
information that may help in brute-force key recovery, or brute force a
session key.
Affected product lines are:
No other Cisco products are vulnerable. It is possible to mitigate this
vulnerability by preventing, or having control over, the interception
of SSH traffic.
Cisco IOS is not vulnerable to any of known exploits that are currently
used to compromise UNIX hosts. For the warning regarding increased
scanning activity for hosts running SSH consult CERT/CC.');
 script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/articles/SSH-Traffic-Analysis");
 script_set_attribute(attribute:"see_also", value: "https://seclists.org/bugtraq/2001/Mar/262");
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20010627-ssh
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?fb584d2f");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00800b168e.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?2ead856a");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20010627-ssh.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/06/27");
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
                  patched: make_list("12.0(20)S") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1DB
if (deprecated_version(version, "12.1DB")) {
 report_extra = '\nNo updates are scheduled for 12.1DB. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1DC
if (deprecated_version(version, "12.1DC")) {
 report_extra = '\nNo updates are scheduled for 12.1DC. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(8a)E") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(6.5)EC3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EX
if (deprecated_version(version, "12.1EX")) {
 report_extra = '\nUpdate to 12.1(8a)E or later\n'; flag++;
}
# Affected: 12.1EY
if (check_release(version: version,
                  patched: make_list("12.1(6)EY") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EZ
if (check_release(version: version,
                  patched: make_list("12.1(6)EZ2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XA
if (deprecated_version(version, "12.1XA")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XB
if (deprecated_version(version, "12.1XB")) {
 report_extra = '\nNo updates are scheduled for 12.1XB. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1XC
if (deprecated_version(version, "12.1XC")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XD
if (deprecated_version(version, "12.1XD")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XE
if (deprecated_version(version, "12.1XE")) {
 report_extra = '\nNo updates are scheduled for 12.1XE. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1XF
if (check_release(version: version,
                  patched: make_list("12.1(2)XF4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XG
if (deprecated_version(version, "12.1XG")) {
 report_extra = '\nUpdate to 12.1(2)XF4 or later\n'; flag++;
}
# Affected: 12.1XH
if (deprecated_version(version, "12.1XH")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XI
if (deprecated_version(version, "12.1XI")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XJ
if (deprecated_version(version, "12.1XJ")) {
 report_extra = '\nUpdate to 12.1(5)YB4 or later\n'; flag++;
}
# Affected: 12.1XL
if (deprecated_version(version, "12.1XL")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XM
if (check_release(version: version,
                  patched: make_list("12.1(4)XM4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XP
if (check_release(version: version,
                  patched: make_list("12.1(3)XP4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XQ
if (deprecated_version(version, "12.1XQ")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XR
if (check_release(version: version,
                  patched: make_list("12.1(5)XR2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XS
if (check_release(version: version,
                  patched: make_list("12.1(5)XS2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XT
if (check_release(version: version,
                  patched: make_list("12.1(3)XT3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XU
if (check_release(version: version,
                  patched: make_list("12.1(5)XU1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XV
if (check_release(version: version,
                  patched: make_list("12.1(5)XV3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XY
if (check_release(version: version,
                  patched: make_list("12.1(5)XY6") )) {
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
# Affected: 12.1YF
if (check_release(version: version,
                  patched: make_list("12.1(5)YF2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(1.1)", "12.2(1b)", "12.2(3)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(2.2)T") )) {
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
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ssh", "show ip ssh");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"version\s+1\.5", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
