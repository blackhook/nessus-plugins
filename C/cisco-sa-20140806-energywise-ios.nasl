#TRUSTED 258dd03a18d83433f04abf311cd8af71b3ed5962f59cc0976e5789c2379a9a386e1a8a9079dbf3846c004e33022f824244ee083f9c495a0da06a989eca355edf5f1ab007462f777b5c3e5381e20c789022ebe64856b5f690f8d7e1dbe48e1818bdb59ef90035a79e1a2e435c6c35184fca35607c6d0c05598451868bfdf357d019b91fc9e0592982b775ccd5f6e8313ea9671cd3013ce6e14daa6e18820315e60a1ff8e5bf506646d07b321ea5c4a59a77c84e7a83b1248a0daa505da2fdf34df465b477c96541639cbfed1a71044295c3870d75bb52e11e8141f2a0be2b2680ebac12370809464642b1ee2c9c444c3ee4cb0461589627e8438b400aeeaabeae6a96a61bd0daa5df23f2f717bbb0fb08e5a4bb1c351d2d6ff5fdfde75ac596c48c54963656e7e6ed7310320fcbc883006a80f3fec3e47407a43073cf2e8897a1d9beb1b9c765663ed5d8179dfa76d51a0ddf87e3b1d89f19227029fb3c774393cd549df854e840e1a866a21dbab120133142a76fffc99a25910456756d6092ecbe5afd581ac28cf8a40d251eb4548ac1604c1ec9b147024c42465fe9e5c745b6ed4faecfcf4b9e9e0a0de495382fa7fb59a7764a830f805b6aa1ad545edecce93180389bc011430c26c4df47401fa859222082c8bffd66623dc7fa8aace0c13194252080ed8b7a59d3231b1f22e811084f9d0bae95bbc62f17d12ca4219ab81c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77153);
  script_version("1.16");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2014-3327");
  script_bugtraq_id(69066);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup52101");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140806-energywise");

  script_name(english:"Cisco IOS Software EnergyWise DoS (cisco-sa-20140806-energywise");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability in EnergyWise module.

The issue exists due to improper handling of specially crafted
EnergyWise packets. An unauthenticated, remote attacker could exploit
this issue to cause a device reload.

Note that this issue only affects hosts with EnergyWise enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140806-energywise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5dbdaa0");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35091");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3327");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
if ( ver == '15.2E' ) flag++;
if ( ver == '15.2(2)E' ) flag++;
if ( ver == '15.2(1)E3' ) flag++;
if ( ver == '15.2(1)E2' ) flag++;
if ( ver == '15.2(1)E1' ) flag++;
if ( ver == '15.2(1)E' ) flag++;
if ( ver == '15.1SY' ) flag++;
if ( ver == '15.1SG' ) flag++;
if ( ver == '15.1(2)SY3' ) flag++;
if ( ver == '15.1(2)SY2' ) flag++;
if ( ver == '15.1(2)SY1' ) flag++;
if ( ver == '15.1(2)SY' ) flag++;
if ( ver == '15.1(2)SG4' ) flag++;
if ( ver == '15.1(2)SG3' ) flag++;
if ( ver == '15.1(2)SG2' ) flag++;
if ( ver == '15.1(2)SG1' ) flag++;
if ( ver == '15.1(2)SG' ) flag++;
if ( ver == '15.1(1)SY3' ) flag++;
if ( ver == '15.1(1)SY2' ) flag++;
if ( ver == '15.1(1)SY1' ) flag++;
if ( ver == '15.1(1)SY' ) flag++;
if ( ver == '15.1(1)SG2' ) flag++;
if ( ver == '15.1(1)SG1' ) flag++;
if ( ver == '15.1(1)SG' ) flag++;
if ( ver == '15.0SE' ) flag++;
if ( ver == '15.0EZ' ) flag++;
if ( ver == '15.0EX' ) flag++;
if ( ver == '15.0EK' ) flag++;
if ( ver == '15.0EJ' ) flag++;
if ( ver == '15.0EH' ) flag++;
if ( ver == '15.0ED' ) flag++;
if ( ver == '15.0(2)SE6' ) flag++;
if ( ver == '15.0(2)SE5' ) flag++;
if ( ver == '15.0(2)SE4' ) flag++;
if ( ver == '15.0(2)SE3' ) flag++;
if ( ver == '15.0(2)SE2' ) flag++;
if ( ver == '15.0(2)SE1' ) flag++;
if ( ver == '15.0(2)SE' ) flag++;
if ( ver == '15.0(2)EZ' ) flag++;
if ( ver == '15.0(2)EX6' ) flag++;
if ( ver == '15.0(2)EX5' ) flag++;
if ( ver == '15.0(2)EX4' ) flag++;
if ( ver == '15.0(2)EX3' ) flag++;
if ( ver == '15.0(2)EX2' ) flag++;
if ( ver == '15.0(2)EX1' ) flag++;
if ( ver == '15.0(2)EX' ) flag++;
if ( ver == '15.0(2)EK' ) flag++;
if ( ver == '15.0(2)EJ1' ) flag++;
if ( ver == '15.0(2)ED1' ) flag++;
if ( ver == '15.0(1)SE3' ) flag++;
if ( ver == '15.0(1)SE2' ) flag++;
if ( ver == '15.0(1)SE1' ) flag++;
if ( ver == '15.0(1)SE' ) flag++;
if ( ver == '12.2SE' ) flag++;
if ( ver == '12.2EZ' ) flag++;
if ( ver == '12.2EY' ) flag++;
if ( ver == '12.2EX' ) flag++;
if ( ver == '12.2(60)EZ4' ) flag++;
if ( ver == '12.2(60)EZ3' ) flag++;
if ( ver == '12.2(60)EZ2' ) flag++;
if ( ver == '12.2(60)EZ1' ) flag++;
if ( ver == '12.2(60)EZ' ) flag++;
if ( ver == '12.2(58)SE2' ) flag++;
if ( ver == '12.2(58)SE1' ) flag++;
if ( ver == '12.2(58)SE' ) flag++;
if ( ver == '12.2(58)EY2' ) flag++;
if ( ver == '12.2(58)EY1' ) flag++;
if ( ver == '12.2(58)EY' ) flag++;
if ( ver == '12.2(58)EX' ) flag++;
if ( ver == '12.2(55)EX3' ) flag++;

# Check that EnergyWise is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config",
                              "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:"^\s*energywise\s+domain", string:buf)     ||
      preg(multiline:TRUE, pattern:"^\s*energywise\s+management", string:buf) ||
      preg(multiline:TRUE, pattern:"^\s*energywise\s+endpoint", string:buf)
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup52101' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected");
