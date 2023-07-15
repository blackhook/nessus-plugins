#TRUSTED 6980c447871d88530e2e14386645059c5509ed6e06b76310610ebd229a3e60880d923458b9075d9f269b4bef7ee9f217e366a4bde98ba0662ef32232c0ceac37f7ad2c1f18812ea5e9eb3ac9559216dd35e9009d7666b1d4f664f614505bec68ceaf0e418d550fcfc9e88b2a3376ba1f45a4e2a9492162e4efd414dd712ffccf307bd7f8370beebf7a9497b1a572eb03f0a1822af4ea63b6b6ed57662a0f01164328c4b1716c13701c5f784f87b2405c5b4a7ae3a59fa975fdc59f83b70ab98e3aba76e8822252113730bcf0133b2cafb60f2afb7eca9bc997d61dec4882799a98b84b034fcb38c10bf33c04da242bdb58f84794d9e8d324d65e3cbc33b4fbe1b0fec63d0fbacf6e7ac9615a976ce8c941b52bd930b136defb07f0b821186a0880c0b61883e6acf3125c71be5fe59914ab554c48d58ceb5f2c18fe4c109eef430ac856184d3f87d079ae3b0d50cc263927ab05ac94ae0222a4deb55fa0e16a25d8c2eee50ce49e7112c216172de9b3301984e9e71df757d88ed852b141d029a8b42d63b3a964d7fdf488d1d8c8a2508c0e059096060ce1b36a600e2e8354a729ba1f93af65e2cbe1517980fd24b1c56c230ee75da23f20b9d3694e5e3046ecb297cfdd61acaa437a3e59cc6671787308583f3730f1f9f5dd448c34f7f8d72a0a592f952cbc32952606fecfaa1bba877ac30a7d8c9b090cf858323db0144e1a5e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91760);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2015-6360");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux04317");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160420-libsrtp");

  script_name(english:"Cisco IOS XE libsrtp DoS (CSCux04317)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing vendor-supplied security
patches, and it is configured to use the Cisco Unified Border Element
(CUBE) or Session Border Controller (SBC) features. It is, therefore,
affected by an integer underflow condition in the Secure Real-Time
Transport Protocol (SRTP) library due to improper validation of
certain fields of SRTP packets. An unauthenticated, remote attacker
can exploit this, via specially crafted SRTP packets, to cause packet
decryption to fail, resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-libsrtp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2658d700");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco Security
Advisory cisco-sa-20160420-libsrtp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6360");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = FALSE;
override = FALSE;

# Fixed: 3.14.3S, 3.13.5S, 3.16.2S, 3.10.7S, 3.17.1S, 3.15.3S
# Check for vuln version

if ( ver == "3.10.01S" ) flag = TRUE;
if ( ver == "3.10.0S" ) flag = TRUE;
if ( ver == "3.10.0aS" ) flag = TRUE;
if ( ver == "3.10.1S" ) flag = TRUE;
if ( ver == "3.10.1xbS" ) flag = TRUE;
if ( ver == "3.10.2S" ) flag = TRUE;
if ( ver == "3.10.2aS" ) flag = TRUE;
if ( ver == "3.10.2tS" ) flag = TRUE;
if ( ver == "3.10.3S" ) flag = TRUE;
if ( ver == "3.10.4S" ) flag = TRUE;
if ( ver == "3.10.5S" ) flag = TRUE;
if ( ver == "3.10.6S" ) flag = TRUE;
if ( ver == "3.13.0S" ) flag = TRUE;
if ( ver == "3.13.0aS" ) flag = TRUE;
if ( ver == "3.13.1S" ) flag = TRUE;
if ( ver == "3.13.2S" ) flag = TRUE;
if ( ver == "3.13.2aS" ) flag = TRUE;
if ( ver == "3.13.3S" ) flag = TRUE;
if ( ver == "3.13.4S" ) flag = TRUE;
if ( ver == "3.14.0S" ) flag = TRUE;
if ( ver == "3.14.1S" ) flag = TRUE;
if ( ver == "3.14.2S" ) flag = TRUE;
if ( ver == "3.15.0S" ) flag = TRUE;
if ( ver == "3.15.1S" ) flag = TRUE;
if ( ver == "3.15.1cS" ) flag = TRUE;
if ( ver == "3.15.2S" ) flag = TRUE;
if ( ver == "3.16.0S" ) flag = TRUE;
if ( ver == "3.16.0aS" ) flag = TRUE;
if ( ver == "3.16.0bS" ) flag = TRUE;
if ( ver == "3.16.0cS" ) flag = TRUE;
if ( ver == "3.16.1S" ) flag = TRUE;
if ( ver == "3.16.1aS" ) flag = TRUE;
if ( ver == "3.17.0S" ) flag = TRUE;

# Check for Smart Install client feature or support of archive download-sw
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_include_sbc", "show running-config | include sbc");
  if (check_cisco_result(buf))
  {
    if (preg(string:buf, pattern:"^\s*sbc [^\s]+", multiline:TRUE)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = TRUE;
    override = TRUE;
  }

  if(!flag)
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_include_srtp-auth", "show running-config | include srtp-auth");
    if (check_cisco_result(buf))
    {
      if (preg(string:buf, pattern:"^\s*(|voice-class sip )srtp-auth( [^\s]+|$)", multiline:TRUE)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf))
    {
      flag = TRUE;
      override = TRUE;
    }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux04317' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
