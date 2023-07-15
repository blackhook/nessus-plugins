#TRUSTED 3a71523fa24918381675dd324efbc95072d089d5052e4f329179936c71dd76c1a9832f9f664e44da86050dc43f289fe55b51a755b19d3e15a711de299f7750958b2e0e1eeff28c2898f7d6a07683f1285c06d24caca91790076caa610ca9cf88a3bb1b9149307275bb8045abd75ba80d5818ccb16e18faf66b90e4a6ab12426d2dc3f3c951e36b296c0af186ec1ef4f590dd8f775158f89b9e6ff9e531f30967e00e2cb65f4cf0f5cbbcb003593e439c419790e18521a3fffd5604270cb1dbe53f059526a385e7735eadb85a4c8acc8dde06630e67defc86586c5eff53d61c6834f234db7c0537d46639d9d3748a5c74a5d97e2f45e7457742565cfab2d0e13852a4a7fa25be10a1f24fa898669f1e9d606be35ace733b81c9cf7f13b2e7f56b83c3011850cceb73d1c45467a46a985c6ad966f3cc3e0f27388e819d705e39875103d7978c099ad3f63d4ebd9eb498085ec5ed709af53c1efc7c817ca6f5446a93e4c263718dfc923e682eae436eab3e5ec360cd15440dcf070b589451ec9a77a369f281be5cbafe0a5c5ff49e41bb6ce413e4d83ae2f5cec7bc0e03b11510f41970794de1d1d3980db5a76d3b59e023bc73713159b7c1809ff985ffdfefd897ecbe09f2c672885093b0a5d00f628d430bbaed7f01a3ba500239b78efefebef531b74236fa6744dd633ea0f76318ce6e32dcb0ef3da9eac3036b681bd6648777
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73347);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-2106");
  script_bugtraq_id(66465);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug45898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-sip");

  script_name(english:"Cisco IOS Software Session Initiation Protocol Denial of Service (cisco-sa-20140326-sip)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability in the Session Initiation Protocol (SIP) implementation.
An unauthenticated, remote attacker could potentially exploit this
issue to cause a denial of service.

Note that this issue only affects hosts configured to process SIP
messages. SIP is not enabled by default on newer IOS versions.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0dba6e85");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-sip.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
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
report = "";
cbi = "CSCug45898";
fixed_ver = "15.3(3)M2";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( ver == '15.3(3)M' || ver == '15.3(3)M1') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (
           (preg(multiline:TRUE, pattern:"CCSIP_UDP_SOCKET", string:buf)) ||
           (preg(multiline:TRUE, pattern:"CCSIP_TCP_SOCKET", string:buf))
         ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) {flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
