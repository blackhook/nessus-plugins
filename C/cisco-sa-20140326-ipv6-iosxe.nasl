#TRUSTED 169e67836c356066715c6e1cee161fa08d491ab11d6605fccec5b9f125d8b1cdc0efa33e3383c9122627d89ef11c688f1d7025881275b840ddd96e9d2a700dec38c134856b072413b21b97628cc854a792b88fd425cb603bc4c12dc4720de6f4a4a4078f9997abeecd999e2a3045925657dce4b316af58647c8e5951ddfdd3e4782a15400c3c2755421521f857555b77cfe2fbad66c01841d775d46487d25f0df288cded2c180488a6fdaf4f01abdb028f4ec1b6ce42ae26d0c5666bd6f9848d883af947a8a01e447b2a96056bbb88836c73c2afda3e783623cd1264c3def767ab218e00a20c0bc25df4f0da0cfee6c9e30eb6e4451f0747bdb3a93816fef85090a0c8cdad8e6339582a0406e8e23a50633750614254c41d94913eaa9048968663508e31bbe1881ed3f80c90888d3bf6e94c07784866ee96bba5f5f80a0c715ce823e3d63b6aacd95af63d91917f29c8dbb5f254b1114faa8fd87ebaeaaae37d061f7c35a64d42da569991d47f7a3f9cbf37f254580b522b5d43582f0a8abdad5f97df999ebc50822f0a321eb31b5061cc1d161786044bee07e6a38aa22970b1db482bdea1f8f1ac5e6216de5de18150d616b6f9b18d99c233e50f93d597cec5ea81a0119c2159162a99ca43940515a42ac167e3e2988a4d09075f5e9444bd724f69a2358be64636b1b46580fea462ee768c29f231641ce46a7a3002b80fcf72
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73343);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-2113");
  script_bugtraq_id(66467);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui59540");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-ipv6");

  script_name(english:"Cisco IOS XE Software IPv6 Denial of Service (cisco-sa-20140326-ipv6");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the IPv6 protocol stack. This issue exists due to
improper handling of certain, unspecified types of IPv6 packets. An
unauthenticated, remote attacker could potentially exploit this issue
by sending a specially crafted IPv6 packet resulting in a denial of
service.

Note that this issue only affects hosts with IPv6 enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ffd6d00");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33351");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-ipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}


include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
report = "";
fixed_ver = "";
cbi = "CSCui59540";

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# 3.7xS
if (ver == '3.7.0S' || ver == '3.7.1S' || ver == '3.7.2S' || ver == '3.7.3S' || ver == '3.7.4S')
         fixed_ver = '3.7.5S';

# 3.5xE
else if (ver == '3.5.0E' || ver == '3.5.1E')
         fixed_ver = '3.5.2E';

# 3.3xXO
else if (ver == '3.3.0XO)')
         fixed_ver = '3.6.0E';

# 3.8xS
else if (ver == '3.8.0S' || ver == '3.8.1S' || ver == '3.8.2S')
         fixed_ver = '3.10.2S';
# 3.9xS
else if (ver == '3.9.0S' || ver == '3.9.1S')
         fixed_ver = '3.10.2S';
# 3.10xS
else if (ver == '3.10.0S' || ver == '3.10.1S')
         fixed_ver = '3.10.2S';



if (fixed_ver) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
    if (check_cisco_result(buf))
    {
      if (preg(multiline: TRUE, pattern:"IPv6\s+is\s+enabled", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
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
