#TRUSTED 1530a4be7a5e13744c867e26d21720598a4b52dcd675fd5a6d66798db9f9bdaeaa69cb4c035892f2c3af4dba425e7093944d528d9787347ee520ad07ad0a19db604fcca7d219dd0352b0c636f794d3df5483bb5d59ad8bd4c857f25a71d534a4bb2b6fe1b34863f4a50ac864d5625e7686627b695d1cfa6e43604e449381bec34a57b9bd2b11a90c34e98555e032b28f19856cfe50131a42aaf3ef0249e19c462b95c2fbdbb4b9234f164322d81fa3c8ed3283729671eea7a5c661c7126c5c5ba23cff5358137242a3dca2b96d8002575bda6b71f51ce3d646f2e5fcaa67bd1992f2864dee796df9f35660271321e9caed0a235f225d285daba3a18c159e5edd6d3b641917d774fbfb4aadf9722e7f31bae1cfd437b429f404d2d8482a7605f719e3a6a954d2bd80af2074b931e49012d18f9528fa1fe9bd36ad6515b2da491961d00d2b059921cab8ea69a5fa8a43e9b8a732adb685441324f6dd1891ee4637d70a38627bf82ff0553f3ee151e9cd51c3ab8903fbf52b4d740a95388d4c594cd4c65b8947822f6cff3a77bd32ce1d622ec9b782fb36e7a51002415785990307db3eefe10da026b298d976ffee490637b7d6e614d855de1f57bf3b4a24af6235c3619058e75382e9cecba6fa9406cf125fd24507d4c092d61439da6a3bf5bea28747bf6bbffc06792306ae8e2bb16e6d1b44f85410f58f102a08df4e3e551733
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20100922-sslvpn.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(17785);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2010-2836");
  script_bugtraq_id(43390);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtg21685");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100922-sslvpn");

  script_name(english:"Cisco IOS SSL VPN Vulnerability (cisco-sa-20100922-sslvpn)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a vulnerability when the Cisco IOS SSL VPN
feature is configured with an HTTP redirect. Exploitation could allow
a remote, unauthenticated user to cause a memory leak on the affected
devices, that could result in a memory exhaustion condition that may
cause device reloads, the inability to service new TCP connections,
and other denial of service (DoS) conditions. Cisco has released free
software updates that address this vulnerability. There is a
workaround to mitigate this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100922-sslvpn
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b67d481a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100922-sslvpn."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '12.4(15)T13' ) flag++;
if ( version == '12.4(20)T5' ) flag++;
if ( version == '12.4(20)T5a' ) flag++;
if ( version == '12.4(22)T5' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\s+http-redirect\s+port.*", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"webvpn", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      m = eregmatch(pattern:"webvpn gateway([^!]+)!", string:buf);
      if ( (!isnull(m)) && ("inservice" >< m[1]) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
