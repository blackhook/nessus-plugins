#TRUSTED 6b921082af1837d76c6a1b28df6517c81ee572fe4a6fad9800bab25de9ad88908d0c1dafc9379768c25af12d25448e3e4de33f774dc77a980b932ae9a0c9671d2629e25a00b00324262de993fb5aee59769e11cf6b36dba5e1301d20c0de66bde31d251a8b587e5ecf1ac12e19e2c6d04aaef07edf04d56bc5dba3064ac5a77e24fd5795fbc8b100b310e8bc021b164b0631e5197d9ca7ccbd0b33db7ace5bc9dc5ed97116f5aedfa29a0d1e5bfdca85d4ee45916a683cd325944e38eacb8e1f3a2d7e88352498782bd97fc5a9b6429b01c7cfa1464815bd41fc7aca071ba2846c675333f63f1785b133b145ebb8c695361d241b5dcce43bc19f1aac1fcaf42100fe57eccd40a382bc473e678a10253fd237a1d808fa257cc2608f68517999fa806c061c0af65dab6392da497518f64165220a98e89fafc26e551e3632e88663a7946ac06b711b36ef443f40a232ada20a5496448baf118b938d4e721c2ee23678579ba178174522dd81734842fdc8e96a909a3ec2a546db28789bcc0eeae4cf75777bd15dfcc00eaf97b74c9a2f42f7f9ac267db89c6fc118fb6124b04b66b867de87ebac686136b72985be6deb712d956579a62c75ff4403fb10147a7a2eb12dc3e4b58dae7a531dd37a2a9df8b23c19c2b72a9af6b3a16f7a3b662584831fbb75c8e0213a30a5711f066bd4379a7409df582e9a9b3c9c3d95696a907f5df9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78028);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3359");
  script_bugtraq_id(70140);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum90081");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-dhcpv6");

  script_name(english:"Cisco IOS XE Software DHCPv6 DoS (cisco-sa-20140924-dhcpv6)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the DHCP version 6 (DHCPv6) implementation due to
improper handling of DHCPv6 packets. A remote attacker can exploit
this issue by sending specially crafted DHCPv6 packets to the
link-scoped multicast address (ff02::1:2) and the IPv6 unicast
address.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-dhcpv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?942aeed1");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35609");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCum90081");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-dhcpv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

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

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCum90081";
fixed_ver = NULL;


if (
  ver =~ "^2\.[16]\.[0-2]$" ||
  ver =~ "^2\.2\.[1-3]$" ||
  ver =~ "^2\.3\.([02]|[01]t)$" ||
  ver =~ "^2\.4\.[01]$" ||
  ver == "2.5.0" ||
  ver =~ "^3\.1\.[0-3]S$" ||
  ver =~ "^3\.[2356]\.[0-2]S$" ||
  ver =~ "^3\.4\.[0-6]S$" ||
  ver =~ "^3\.7\.[0-4]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.2\.[0-3]SE$" ||
  ver =~ "^3\.3\.[01]SE$"
)
  fixed_ver = "3.3.2SE";

else if (
  ver =~ "^3\.3\.[0-2]SG$" ||
  ver =~ "^3\.4\.[0-3]SG$"
)
  fixed_ver = "3.4.4SG";

else if (ver == "3.3.0XO")
  fixed_ver = "3.3.1XO";

else if (ver =~ "^3\.5\.[01]E$")
  fixed_ver = "3.5.2E";

else if (
  ver =~ "^3\.8\.[0-2]S$" ||
  ver =~ "^3\.9\.[01]S$" ||
  ver =~ "^3\.10\.(0|0a)S$"
)
  fixed_ver = "3.10.4S";

else if (ver =~ "^3\.11\.[12]S$")
  fixed_ver = "3.12.0S";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# DHCPv6 check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_dhcp_interface", "show ipv6 dhcp interface");
  if (check_cisco_result(buf))
  {
    # DHCPv6
    if (preg(multiline:TRUE, pattern:"^Using pool: DHCPv6-stateful", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because DHCPv6 is not enabled.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + 
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
