#TRUSTED aa6280335a3b86ef7c22ade3a03e8914b63ac0debdfeeb4e7e9e08b61794a76ce4cf7b2b28983cb14929efe62b3d8609d485f0b629909b6dc0c4ecf48768c5ed7e40c547127c405deb3b9615413d1955c94e09e53c549b40d933d4d96f2fe8a3a7f6bc2a3aa0f83f9904f0e9b9cc95da307becd297588612d171e34c3d8c95b99f15c31534c484e5919b98d5828b90ed0703eed74223b348fb217f076d106028eff785658c9117efabf3138dbbd6ec5436d1afb266736311f215e7a6e7cd6ab51c263da50ecb188fabf303eb6fadd67e49aab4d006f6c6dc3b3c1621e1dab38e1e6c5e80abc7a00ab88af3fe29e85669fb637809e52cdaf5e9bd6c8a1a4b54e52836d8da3ce7e28585391b51ad1558e5d977b7c08004a1e4dcfdeb7cc746eb9006a778d3fc14a217920a90a7fc9d03c6b8f4de253225813b6b775f00c32f35cbb13eae53dddec7c9c2b4a4e205216f6163f81be1ab194333d4f20be2d54c6d746a636c25a3eddb6c910c46487c6a740e34ee35ed22048ca119201148bd168cd78d2fd685326689a33b68f3018d40cace8541ca1847e392077bc6154a2257d657915df09b35a7b0ff5a6e35084f05e919a24930f1f1d794a2bf4ff9e8692ada2e564466c1f7b6c41203715de7ac351fbeb36dc5cad031608c926032fe091dbc605e77bc86024056b89e4e9e912508c537c7bfd674cdb6dc544718840744d30647
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87820);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2015-6429");
  script_bugtraq_id(79745);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw08236");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151218-ios");

  script_name(english:"Cisco IOS Software IKEv1 State Machine DoS (CSCuw08236)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Internet Key Exchange version 1 (IKEv1) subsystem due to
insufficient condition checks in the IKEv1 state machine. An
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
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6429");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# Check for vuln versions
if (
  ver == '15.4(3)S' ||
  ver == '15.5(3)M' ||
  ver == '15.5(3)M1' ||
  ver == '15.5(1)S' ||
  ver == '15.5(2)S' ||  # Maps to IOS XE 3.15.0S
  ver == '15.5(2)S1' || # Maps to IOS XE 3.15.1S
  ver == '15.5(2)S2' || # Maps to IOS XE 3.15.2S
  ver == '15.5(3)S' ||  # Maps to IOS XE 3.16.0S
  ver == '15.5(3)S1' || # Maps to IOS XE 3.16.1S
  ver == '15.5(1)T' ||
  ver == '15.5(2)T' ||
  ver == '15.6(1)S' ||  # Maps to IOS XE 3.17.0S
  ver == '15.6(1)S1' || # Maps to IOS XE 3.17.1S
  ver == '15.6(1)T0a'
) flag++;

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
      flag = 1;
      cmds = make_list(cmds, "show ip sockets");
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  if (!flag)
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
    if (check_cisco_result(buf))
    {
      if (
        preg(multiline:TRUE, pattern:pat, string:buf)
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
