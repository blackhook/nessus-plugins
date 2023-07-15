#TRUSTED 989369b1b26436b870ed44c5a4ed80db1a10793ef8ce6460cc9d393b77999140b3c7752cf1445183d394ffa8a9a31a0322dd39b1871a219945e50ce44588d78aa490313e5d1a1fcbe29e384b2ce8d01eb1b56ad4a989295ba760e1b423dce0846318a0946a7ccdf3559cd2fce963cf46733103b54a4b30e8e32309af9129d52ecfb09f216f91df9d2ce9e8c4c46df900cc52bf1df815007ab6a58b76ea698fee9565b70b34ecda837381ede58875c5115558eb14693b0b9e967679d46e4301716c1e65c6646cc1ed91afc50faea21b0b6ecc852780ef2f6fffc644af071dfd6ea5f895a76d5c442393414696f632351220e89c793ec40dacb85e01446abf3a6ff7ea95db8acbd63796976ac0afb64575c6068de66471dda35f52ce0b04297a5bec590f6c152009d353c5e062367fa0ddbe50e15ec1ca21de38b3659a8f44e16c8154286752cb0d34fc0ab4f6d56dfd09e633fdfc0be8a24c9813235da8f31b0e4126efaf265e6d083f02f448a626e3549d4210cc83a85eed80b81d31dff42d291269b0509248f9876a5e96fdaf92d5ed9915c8a05e0ca56843fc2ec884d5bdfd49dac3ba65f59a0c35f729b5319192ed890094691241c27da12d0953f36ff50bb0e99ada762d4eae0bea8a85b2c59dddc60b5e2fb1cfde7bf0438cc34dab7d9ba11e395658afe244d1c2afe5a591555f356eda27fd2a9265f73bfaff4fc3580a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93193);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-1478");
  script_bugtraq_id(92317);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva35619");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160804-wedge");

  script_name(english:"Cisco IOS XE NTP Packet Handling Remote DoS (cisco-sa-20160804-wedge)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by a denial
of service vulnerability due to insufficient checks on clearing
invalid Network Time Protocol (NTP) packets from the interface queue.
An unauthenticated, remote attacker can exploit this to cause an
interface wedge, resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160804-wedge
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57eccdac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva35619.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

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

flag = 0;
override = 0;

# Check for vuln version
if ( ver == '3.16.3S' ) flag++;
if ( ver == '3.17.2S' ) flag++;
if ( ver == '3.18.1S' ) flag++;
#if ( ver == '?.?.?' ) flag++; # 15.6(2)T1 IOS == ? IOS XE

# NTP check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status", "show ntp status");
  # Check for traces of ntp
  if (check_cisco_result(buf))
  {
    if (
      "%NTP is not enabled." >< buf &&
      "system poll" >!< buf &&
      "Clock is" >!< buf
    ) audit(AUDIT_HOST_NOT, "affected because NTP is not enabled");
  }
  else if (cisco_needs_enable(buf)) override = 1;
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCva35619",
    cmds     : make_list("show ntp status")
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
