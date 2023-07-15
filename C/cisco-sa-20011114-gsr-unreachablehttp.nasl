#TRUSTED 32ca9d89ba01a2131dbc6363bee454b39db1165ef343f4475bad72fdc38dcccd24e32f8aabf4a65656a2edfe4a93784b97acd7c62e53ac6fb833908133b85db922c9480120bd414f7f2068f09ad624e5cdc194a255eaa6d9671622fc836d4bcb1fbcd80587b61f9b0ae57a911d97704c21ff29fc3926f02bab6fb3cda83c42f261d00ff86b8998b3bb5464b7278814af14c2f816cf16551c512683968f4e4e305cc877eae365fb2ecfa7e0179d708f2ebed03056adf17515858386c59daf003cf3b622160ad7347dd2f9c8667b457dd3997f41db804570c4ec214ee7399d082e1f579718e605f0131405ee7502609992d0b594e0e1eddf8f37b226f4de18ade14300d44be0837003cbd50d5386d24bcbc6c61ca050f55cdfddbb1a75d33f354bbc128e96c3f57e23a7402bf9a620cc749927eb5f9c26ea81aafce699a9c6223a24d5b0ce3ec106f3c0cf956cbf67ebfbc7c5c3691f2b24a982ea0f98e3b6d968081c1bbf04d3a22f425fa63b5bba9a77a4967ae2ca87729d88ffb49cfee9808eaf7186aa1df3fd25d75de15cf495de62be7f48d243d193cc4ff05e3d06b0686eb3ea37b64c68455277cd1fefed1d8c82f187b8cc651ad2c67c8194369543bcd6596732cf36b4948d5000e31dc8a52229a51c38bce97d94b0f0a43de68e6939b1366d1a8915c84cc256531de577b21fcf08fb7bac722e2641c08454c021ef83eb
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080094250.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48960);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2001-0861");
 script_bugtraq_id(3534);
 script_name(english:"ICMP Unreachable Vulnerability in Cisco 12000 Series Internet Router - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'The performance of Cisco 12000 series routers can be degraded when they
have to send a large number of ICMP unreachable packets. This situation
usually can occur during heavy network scanning. This vulnerability is
tracked by three different bug IDs: CSCdr46528 ( registered customers
only) , CSCdt66560 ( registered customers only) , and CSCds36541 (
registered customers only) . Each bug ID is assigned to a different
Engine the line card is based upon.
The rest of the Cisco routers and switches are not affected by this
vulnerability. It is specific for Cisco 12000 Series.
No other Cisco product is vulnerable.
The workaround is to either prevent the router from sending unreachable
Internet Control Message Protocol (ICMPs) at all or to rate limit them. ');
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20011114-gsr-unreachable
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a091c44c");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080094250.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?61ae55cf");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20011114-gsr-unreachable.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/11/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdr46528");
 script_xref(name:"CISCO-BUG-ID", value:"CSCds36541");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt66560");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20011114-gsr-unreachable");
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

# Vulnerability CSCdr46528
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(16)S1", "12.0(16.5)S", "12.0(17)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(15.6)ST3", "12.0(16)ST", "12.0(16.5)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCds36541
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(13.6)S2", "12.0(14)S", "12.0(14.1)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(14.3)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdt66560
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(16)S1", "12.0(16.6)S", "12.0(17)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_diag", "show diag");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"L3\s+Engine:\s+0", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"L3\s+Engine:\s+1", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"L3\s+Engine:\s+2", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
