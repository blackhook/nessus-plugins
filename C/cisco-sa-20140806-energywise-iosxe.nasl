#TRUSTED 8cb70d9df43b055305effc431daa9fec3ffa92fa4a20c840d64c7af107042ad209fd83eb1aee0b452371b01efebb62223116949e137a7d2ea214a18b797cc3dd088791ea2a9426dc31240b72dd6312ff1803c31ef663987914ac8d84ae1db1b4e4d5877f05a6abbbc032aaa8660ed9f8a471514fd6b41c568af67e59aa055aa77f96460ea189e82518353d025ceb7316104de7386d3c0811ef2335a6f420a96e1832e57d6c238a9cfbd1e4794b44d857f5f3de5a2c8a2e96c3b0458f009ec2a10887965648792e10d67da7f34ab83854312c542f187e143692daf15110163c13b8e4c4a302d59746bb49a05980e2a0df5b8fc13082cac9a61b5cd1cf82be82edbce608efdb8214f0180fc92c0ed2165209c254e4db637040c808cc8ddf3626c9ebc4ac234bcd77f754f03d20047101889176fc647e95d418b6c6594a23587af0e3069b266ab63c3619e8ec74b2ab6b0dab41f57f9ce069b74f15ed2ec0243777424150c4e023dc76dbc9f500d94e5a719218a60606878fadc7ab9c1092532a191cf04a41506f77f1c8c1d8daf880b22498d90c55cfe2ed10906050063fc535643ffa8293e50a9bc52451720831115468e1758ab8c5ec5c7a4e380618de2d2e7f3cf428b0592daebaf54046f0aa3bca6d99affd2a4e6747d3fabd1f096506c263ddc3883cc12e2c72fd6bc360c2b9e2fc980150ce6d919daaadda18905cb85e1a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77154);
  script_version("1.17");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2014-3327");
  script_bugtraq_id(69066);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup52101");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140806-energywise");

  script_name(english:"Cisco IOS XE Software EnergyWise DoS (cisco-sa-20140806-energywise");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in EnergyWise module.

The issue exists due to improper handling of specially crafted
EnergyWise packets. An unauthenticated, remote attacker could exploit
this issue to cause a device reload.

Note that this issue only affects hosts with EnergyWise enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140806-energywise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5dbdaa0");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35091");
  # https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/release/note/OL_27989-01.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f8a44d6");
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# The following versions of IOS XE are vulnerable :
#   - 3.2.xXO
#   - 3.3.xSG
#   - 3.4.xSG < 3.4.5SG
#   - 3.5.[012]E
if ( ver =~ "^3\.2\.[0-9]XO$" ) flag++;
if ( ver =~ "^3\.3\.[0-9]SG$" ) flag++;
if ( ver =~ "^3\.4\.[0-4]SG$" ) flag++;
if ( ver =~ "^3\.5\.[0-2]E$" ) flag++;

# Check that EnergyWise is running since it is not
# enabled by default.
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
