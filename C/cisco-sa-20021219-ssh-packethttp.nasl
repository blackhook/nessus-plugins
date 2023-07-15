#TRUSTED 908c731acc3263aa69b15d28b0d7ecbc7c3afaf25920b459edab4e15e6145545426db6d2cf7f754853e70c6e7f8bb9158281b3051884217db4f11256fb2015ce33f79b6c55ec6479a5384270cfd2f5c891d76c06a1f72d098d7351531e3459159183f52d76b31c7ad773050b51fce1486aa236b90e4f40bcc7dee5a0f510d8702a443ef27d3d6690d9c7cbdca9d966cbe2476b049eb7128916f7892783e789f5a1542eb2a532b4b073e00ece5c9154c6f59e34d2390a80c31d616a421348f29510ccd85f569b1dc1a25e7ab2e4bd86e8007e2db977166465c731b3c51922e36e38306fbc54cd94afd40665183cefab2fe51cfcf88d01e07532f4da9a658adf06cef38f6e9f2fa3c7c80efe7fb1c0b64e0b0ce714b6e5e38bf78975e073cdbf77cc7897fb4936ccbc4df342154fd27ad1345932c6e8fb401b7d7a3e1a06737b67a9dccfd3d0784b6dc1dd5e97de8cb3bcf302b6d44a561548215e91b47a9f4261798076a92461e95e27e454dded667e3fda27438d71ce06cd746b859509ed6d0adf1941804e8cd3cdca087c00eb3fb002a61baea7e551c5e967650fee7d948d61bf331dbf6ff774d298b61385da65953b70f4753cd70c43510fdcca5b00384c1e8d9f555b07f99afd0cbad4e6ef2dc6d1dbb7f4945abb23968df6f6c216999898a8b217a057c43a33b40243fa304998c5ad73079e1a3da4f370aa40e57ddffa0e
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a008011c3b4.shtml

include("compat.inc");

if (description)
{
  script_id(48968);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2002-1357", "CVE-2002-1358", "CVE-2002-1359", "CVE-2002-1360");
  script_bugtraq_id(6405, 6407, 6408, 6410);
  script_xref(name:"CERT-CC", value:"389665");
  script_xref(name:"CERT-CC", value:"CA-2002-36");
  script_xref(name:"CISCO-BUG-ID", value:"CSCdu75477");
  script_xref(name:"CISCO-BUG-ID", value:"CSCdy87221");
  script_xref(name:"CISCO-BUG-ID", value:"CSCdz07673");
  script_xref(name:"CISCO-BUG-ID", value:"CSCdz60229");
  script_xref(name:"CISCO-BUG-ID", value:"CSCdz62330");
  script_xref(name:"CISCO-BUG-ID", value:"CSCdz66748");
  script_xref(name:"CISCO-BUG-ID", value:"CSCeb16775");
  script_xref(name:"CISCO-BUG-ID", value:"CSCed38362");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20021219-ssh-packet");

  script_name(english:"SSH Malformed Packet Vulnerabilities - Cisco Systems");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Certain Cisco products containing support for the Secure Shell (SSH)
server are vulnerable to a Denial of Service (DoS) if the SSH server is
enabled on the device. A malformed SSH packet directed at the affected
device can cause a reload of the device. No authentication is necessary
for the packet to be received by the affected device. The SSH server in
Cisco IOS is disabled by default.

Cisco will be making free software available to correct the problem as
soon as possible.

The malformed packets can be generated using the SSHredder test suite
from Rapid7, Inc. Workarounds are available. The Cisco PSIRT is not
aware of any malicious exploitation of this vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.rapid7.com/security-center/advisories/R7-0009.jsp");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20021219-ssh-packet
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc3e11cf");
  # https://www.cisco.com/en/US/products/products_security_advisory09186a008011c3b4.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4184156c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20021219-ssh-packet");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PuTTY Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/19");
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
if (check_release(version: version,
                  patched: make_list("12.0(21)S6", "12.0(22)S4", "12.0(23)S2"),
                  oldest: "12.0(5)S")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(20)ST7", "12.0(21)ST6"),
                  oldest: "12.0(16)ST")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(13)E3", "12.1(14)E1"),
                  oldest: "12.1(5a)E")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EA
if (check_release(version: version,
                  patched: make_list("12.1(13)EA1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 report_extra = '\nNo fix is available for 12.1T releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(12b)", "12.2(13a)"),
                  oldest: "12.2(1)")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(14)S"),
                  oldest: "12.2(1)S")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(11)T3", "12.2(13)T1") )) {
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

