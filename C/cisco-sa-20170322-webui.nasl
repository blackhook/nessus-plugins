#TRUSTED 37f1cba6d6ba4dbe36eb7024978a1c9d4f378a50bcab57b54604e7a9961e658917508308ad9889dcd7529a91dc5d53e2fc6d32bcfbd57051dc055bf78a2198016021860efb09beae8c5a7e8a81492f7de1c2b7eafb22f59579c2ab49b2c52c6e5be9388e8482ee9aed24cd974b6b1202c92b98934e5045e8c04130e0d2dfd2db384d8ff0e848ee7251827ec5b7512252b47b17a54081c4195ff46403666df54138a8372cbfec6b140606ca31290a2d14d7a82e7fdb257798df1dab820521e8aa9481eb94ddc5dfd4fb1e2c5c9ea911049a26db15d575db0dc46a6e9871763de3c25bf883f2524d2ee7d35d23b399c0718cfdf4974d62e8a2b25371b45b3d8e5be5489de5f7038182cbcda1633fa6fcda8ba78abc65b23edd2d54e5678799a09ed85945c315d385970d7095d7db52c36afe1a9af8be26165206f6bbfb7a4b71f8e5254d03126cd9cac20fdb7d8b9c3e86f7bde214628e64408be5156c7a0f11c141571eb7dc3b993c92deab9115eb6c9266c0eb39163408c2156132847aa1ab32f5064598fa21071eaadea0ccf2c9b022dc904e4656691000cd3f5b086451a146a654ff89d0a2624722bbf6c74cea77c5bf3377e7780d24d6b186b0174edefc234224a33c3c0d57205d1202b46ae321aa85c1e6aa7709603f7899aae7eefaa84d72ad12d232f935b980f96513f0ce7de4cfa750d036dc77e66a91695e31be8aa3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99031);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3856");
  script_bugtraq_id(97007);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup70353");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-webui");

  script_name(english:"Cisco IOS XE Web User Interface DoS (cisco-sa-20170322-webui)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the web user interface due to insufficient resource
handling. An unauthenticated, remote attacker can exploit this issue,
by sending a high number of requests to the web user interface, to
cause the device to reload.

Note that for this vulnerability to be exploited, the web user
interface must be enabled and publicly exposed. Typically, it is
connected to a restricted management network. By default, the web user
interface is not enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-webui
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?072bd138");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCup70353");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCup70353.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (
  ver == "3.1.0S" ||
  ver == "3.1.0SG" ||
  ver == "3.1.1S" ||
  ver == "3.1.1SG" ||
  ver == "3.1.2S" ||
  ver == "3.1.3aS" ||
  ver == "3.1.3S" ||
  ver == "3.1.4aS" ||
  ver == "3.1.4S" ||
  ver == "3.10.0S" ||
  ver == "3.10.1S" ||
  ver == "3.10.1xbS" ||
  ver == "3.10.2S" ||
  ver == "3.10.2tS" ||
  ver == "3.10.3S" ||
  ver == "3.10.4S" ||
  ver == "3.10.5S" ||
  ver == "3.10.6S" ||
  ver == "3.10.7S" ||
  ver == "3.10.8S" ||
  ver == "3.11.0S" ||
  ver == "3.11.1S" ||
  ver == "3.11.2S" ||
  ver == "3.11.3S" ||
  ver == "3.11.4S" ||
  ver == "3.12.0aS" ||
  ver == "3.12.0S" ||
  ver == "3.12.1S" ||
  ver == "3.12.2S" ||
  ver == "3.12.3S" ||
  ver == "3.12.4S" ||
  ver == "3.13.0aS" ||
  ver == "3.13.0S" ||
  ver == "3.13.1S" ||
  ver == "3.13.2aS" ||
  ver == "3.13.2S" ||
  ver == "3.13.3S" ||
  ver == "3.13.4S" ||
  ver == "3.14.0S" ||
  ver == "3.14.1S" ||
  ver == "3.14.2S" ||
  ver == "3.14.3S" ||
  ver == "3.14.4S" ||
  ver == "3.15.0S" ||
  ver == "3.15.1cS" ||
  ver == "3.15.1S" ||
  ver == "3.15.2S" ||
  ver == "3.15.3S" ||
  ver == "3.16.0cS" ||
  ver == "3.16.0S" ||
  ver == "3.16.1aS" ||
  ver == "3.16.1S" ||
  ver == "3.17.0S" ||
  ver == "3.17.1aS" ||
  ver == "3.17.1S" ||
  ver == "3.17.2S " ||
  ver == "3.17.3S" ||
  ver == "3.2.0JA" ||
  ver == "3.2.0SE" ||
  ver == "3.2.0SG" ||
  ver == "3.2.0XO" ||
  ver == "3.2.11SG" ||
  ver == "3.2.1S" ||
  ver == "3.2.1SE" ||
  ver == "3.2.1SG" ||
  ver == "3.2.1XO" ||
  ver == "3.2.2S" ||
  ver == "3.2.2SE" ||
  ver == "3.2.2SG" ||
  ver == "3.2.3SE" ||
  ver == "3.2.3SG" ||
  ver == "3.2.4SG" ||
  ver == "3.2.5SG" ||
  ver == "3.2.6SG" ||
  ver == "3.2.7SG" ||
  ver == "3.2.8SG" ||
  ver == "3.2.9SG" ||
  ver == "3.3.0S" ||
  ver == "3.3.0SE" ||
  ver == "3.3.0SG" ||
  ver == "3.3.0SQ" ||
  ver == "3.3.0XO" ||
  ver == "3.3.1S" ||
  ver == "3.3.1SE" ||
  ver == "3.3.1SG" ||
  ver == "3.3.1SQ" ||
  ver == "3.3.1XO" ||
  ver == "3.3.2S" ||
  ver == "3.3.2SE" ||
  ver == "3.3.2SG" ||
  ver == "3.3.2XO" ||
  ver == "3.3.3SE" ||
  ver == "3.3.4SE" ||
  ver == "3.3.5SE" ||
  ver == "3.4.0aS" ||
  ver == "3.4.0S" ||
  ver == "3.4.0SG" ||
  ver == "3.4.0SQ" ||
  ver == "3.4.1S" ||
  ver == "3.4.1SG" ||
  ver == "3.4.1SQ" ||
  ver == "3.4.2S" ||
  ver == "3.4.2SG" ||
  ver == "3.4.3S" ||
  ver == "3.4.3SG" ||
  ver == "3.4.4S" ||
  ver == "3.4.4SG" ||
  ver == "3.4.5S" ||
  ver == "3.4.5SG" ||
  ver == "3.4.6S" ||
  ver == "3.4.6SG" ||
  ver == "3.4.7SG" ||
  ver == "3.4.8SG" ||
  ver == "3.5.0E" ||
  ver == "3.5.0S" ||
  ver == "3.5.0SQ" ||
  ver == "3.5.1E" ||
  ver == "3.5.1S" ||
  ver == "3.5.1SQ" ||
  ver == "3.5.2E" ||
  ver == "3.5.2S" ||
  ver == "3.5.2SQ" ||
  ver == "3.5.3E" ||
  ver == "3.5.3SQ" ||
  ver == "3.5.4SQ" ||
  ver == "3.5.5SQ" ||
  ver == "3.6.0E" ||
  ver == "3.6.0S" ||
  ver == "3.6.1E" ||
  ver == "3.6.1S" ||
  ver == "3.6.2aE" ||
  ver == "3.6.2S" ||
  ver == "3.6.3E" ||
  ver == "3.6.4E" ||
  ver == "3.6.5aE" ||
  ver == "3.6.5bE" ||
  ver == "3.6.5E" ||
  ver == "3.7.0bS" ||
  ver == "3.7.0E" ||
  ver == "3.7.0S" ||
  ver == "3.7.1E" ||
  ver == "3.7.1S" ||
  ver == "3.7.2E" ||
  ver == "3.7.2S" ||
  ver == "3.7.2tS" ||
  ver == "3.7.3E" ||
  ver == "3.7.3S" ||
  ver == "3.7.4E" ||
  ver == "3.7.4S" ||
  ver == "3.7.5S" ||
  ver == "3.7.6S" ||
  ver == "3.7.7S" ||
  ver == "3.8.0E" ||
  ver == "3.8.0EX" ||
  ver == "3.8.0S" ||
  ver == "3.8.1E" ||
  ver == "3.8.1S" ||
  ver == "3.8.2E" ||
  ver == "3.8.2S" ||
  ver == "3.9.0E" ||
  ver == "3.9.0S" ||
  ver == "3.9.1S" ||
  ver == "3.9.2S"
)
{
  flag++;
}

cmds = make_list();
# Check if the web user interface is enabled and configured
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include http|transport","show running-config | include http|transport");
  if (check_cisco_result(buf))
  {
    if (
      ("transport-map type persistent webui" >< buf) &&
      ("transport type persistent webui input" >< buf) &&
      ("ip http server" >< buf || "ip http secure-server" >< buf)
    )
    {
      cmds = make_list(cmds, "show running-config | include http|transport");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCup70353",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
