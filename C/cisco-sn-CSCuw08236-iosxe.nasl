#TRUSTED 27bddc3cf364454f6c96289a8a7a920464b436db0d034ffbce50260da8e42141c21e7b032cf0826f80a79d3d3a8f930522ccc4fe74d6f7e85d928db9d026afb9544917da208831d928346458a9ad8ab2ba2d3879238f1d530c58cac767933df4ee4e755062fa310b24df48d5f9f99a90ee00eb5db3a7a54302080db997677a0e653db5f13477b8dac33b93f6aefe401127c653b3a4b9530c7c86546d085eb5fb3390af2cab2e3f8ca258675d6fb55787b1cef8284da98107004c58ba6a17ab063085983940048e5cfb8ef9c92972c100ec55d728c0c9808a9e5bed980b38e1a2ba93be622acfd7b375d3ed3f2fcdb141ce08d9825838e3fe62b9017c9194976aa03edada4bb63648710603358b02c5a5368aadbb345338a1dc296e49cec025438e64e18189e11174bf0cbb98ccaa41080558a7efaaf24959e679593d47c0209b50da2ebe547ef82243c06a7902eeb8a52473af0ed171eec4169806f31dc59f1e587071039a1150e2797f6ed58340a21cd0cd1fd1f97935fa3fa56b6a8d891737adae78dd2cb677fbeff2d3e1c15431e68433b55e90fd749daa5163b06bd0bd1bf581b6eff035f84917980fac560b725558483fd67397c78a82202c81311b067c9de97c93563fb0919d7ce0f85a9164ffe756e313c842b6ca17a43a81a2eac82b18f3f04d569fe90a8900e9a48530ca3678eac8579ac789f175e6b68b5c3452a0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87821);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-6429");
  script_bugtraq_id(79745);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw08236");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151218-ios");

  script_name(english:"Cisco IOS XE Software IKEv1 State Machine DoS (CSCuw08236)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Internet Key Exchange version 1 (IKEv1) subsystem
due to insufficient condition checks in the IKEv1 state machine. An
unauthenticated, remote attacker can exploit this vulnerability, by
sending a spoofed, specific IKEv1 packet to an endpoint of an IPsec
tunnel, to tear down IPsec tunnels that terminate on the endpoint,
resulting in a partial denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151218-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b10e25c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw08236");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20151218-ios.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");

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


# 3.15.2S / 3.16.1S / 3.17.1S Labeled not-vuln in SA
if (
  # CVRF IOS XE unmapped
  ver == "3.15.0S" ||
  ver == "3.15.1S" ||
  ver == "3.17.0S" ||
  ver == "3.16.0S" ||

  # CVRF IOS XE mapped (via cisco_ios_xe_version.nasl)
  ver == "3.13.0S" || # IOS 15.4(3)S
  ver == "3.14.0S"    # IOS 15.5(1)S
)
{
  flag++;
}

cmds = make_list();
# Check that IKEv1 or ISAKMP is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500)\s";

  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:pat, string:buf)
    )
    {
      cmds = make_list(cmds, "show ip sockets");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s500\s", string:buf) ||
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s848\s", string:buf) ||
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s4500\s", string:buf)
    )
    {
      flag = 1;
      cmds = make_list(cmds, "show udp");
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : ver,
    bug_id   : "CSCuw08236",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
