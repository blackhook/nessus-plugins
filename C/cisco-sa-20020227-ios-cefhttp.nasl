#TRUSTED acd6c78aee15744e22dcdfa475f2b3e7aff7d8581fd28160409ed51c9e5fe85fda1cf64eb3fa0c96714f9f0dea47710bd4b3ddc306bc0a2bd3611437f2a865e3421f25167a4e4c23adad4446d7e0677b1cf915369220ceb73f345d99d0e256aa79b71e2e9f4c752c190dc42a915883f93c16379351429245ba8d1e177920a53b612109a1d414078e55ddafac9b12808692224805c055ccff4a1c00d97d6fcfc64e7d2e4170fd9496aa6c6f77d22b828f3d8d496c6e4fb0afa1588c932e7668a79a21361b27c4fdfffe692676f1f33610e44dd8e6407fdbf52921973226bca448e86697942ec8d57c2d40b601c8b89d1541ac5cd02ac509fd27ac213a40a6ee96631885b54dff11e53506a241803784b000b0bc99c94061e262a7092a85bce71fbf25f58e9768a861ff554ebd7d176e409ab916d2250171a9e966f31ab4b878cecc4a575ef8f0d7dc67b023213a92e95f7bf04ace229f0200652f9ce39072978e6274013ee9ce690117278e4ed48e3163ddd3474b7b118bc3c67f285efc45883d1cfd5c6921f7ff11d14a36bddf8825c0a03bd4009569eb04fa29c5d18663e7560b5b99f741f12cce12b85213ffd29eab8e5560849a45c193efa4cc49fe9a9619e2103b6a8da52ce9544c5ec81c5167d383d56d5420397770eccfef0b7b20f9f1f195f92bda1a2022b76abd767de1bdb747e1a85baad7d9507991fbd9caafb15c
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080094716.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48964);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2002-0339");
 script_bugtraq_id(4191);
 script_xref(name:"CERT", value:"310387");
 script_name(english:"Data Leak with Cisco Express Forwarding Enabled - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'Excluding Cisco 12000 Series Internet Routers, all Cisco devices
running Cisco IOS software that have Cisco Express Forwarding (CEF)
enabled can leak information from previous packets that have been
handled by the device. This can happen if the packet length described
in the IP header is bigger than the physical packet size. Packets like
these will be expanded to fit the IP length and, during that expansion,
an information leak may occur. Please note that an attacker can only
collect parts of some packets but not the whole session.
No other Cisco product is vulnerable. Devices that have fast switching
enabled are not affected by this vulnerability. Cisco 12000 Series
Internet Routers are not affected by this vulnerability.
The workaround for this vulnerability is to disable CEF.
');
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020227-ios-cef
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?680f78f5");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080094716.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?5e26ba6c");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20020227-ios-cef.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/27");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/02/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdp58360");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu20643");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20020227-ios-cef");
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

# Affected: 11.1CC
if (check_release(version: version,
                  patched: make_list("11.1(36)CC3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(20.4)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(18.3)S", "12.0(19)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(18.3)ST", "12.0(19)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0T")) {
 report_extra = '\n12.0T releases are vulnerable. Contact Cisco for a fix\n'; flag++;
}
# Affected: 12.0W5
if (check_release(version: version,
                  patched: make_list("12.0(20.4)W5(24.7)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(9.2)", "12.1(10)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(8.5)E2", "12.1(8a)E","12.1(9.5)E"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(7.5)EC1", "12.1(9.5)EC") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 report_extra = '\n12.1T releases are vulnerable. Contact Cisco for a fix\n'; flag++;
}
# Affected: 12.1XM
if (check_release(version: version,
                  patched: make_list("12.1(5)XM6") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(2.5)", "12.2(3)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(3.3)S") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(2.4)T", "12.2(4)T"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_cef_detail", "show ip cef detail");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"CEF\s+is\s+enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
