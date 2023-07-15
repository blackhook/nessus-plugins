#TRUSTED 241f359f528921b9a8f615166c910d73a3286c82dc89cbd22f7c560ebfeba8b7a9b8dfc656de101adde93cdf87b1260c54593b6730a50328595becb464541f953fd17f09564d41fead3be41007c6a3f421ce4784aee31ca12fd30e519542b606ebf5ccf02e9b67b5da90709638bb85fdfddb9ef0bccc5e7e5fe4d7753f032214675d688754f157758378374b770a488eb475719e9044faee2c29bba96f6bd8091fc310e197ea89d6472a2d3d3989669b62b4e08381856908b56d71dc6fa15879141788a96c1b86598b6f088f2103a80474578a2f8138dfcdefcbb9a215b231b057f4aa735073a215690d85fe5ee7471230c1d4fe0ee17c5e2cf350be6b96ab5ceff0df61fb7dbb19e48a6fbfc63db5e4cf29cdf2e185d67e760029c5a8de761c65fc03cd55edd43953205e5c745a85727637834e813d54432376891cad7ba75eefe2a22c4f4889d74e290bd5876f7470e33aa2c28e2ee6682ff697d7ad94143273f58733042702248d7f6cca671a675ae5d68b61261a342e963bc476c532ee03faf9db4ccae149da546390a2d7bcbbb7c8f33d3e251a4bd3fdd2d16635329f9321b980ac02c64b18bb47ee2f4ab21dc956de3b881decaf1b29d734997aa6214dc705ac8500896895573324a850fa4ccd5e0e1c59407209f5036a340100b0cbe46a4ad1f1eccfae285097cd839003fed6b9c7e4fa332a74ca337bd08f40529efc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99032);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3858");
  script_bugtraq_id(97009);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy83069");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-xeci");

  script_name(english:"Cisco IOS XE HTTP Parameters Command Injection (cisco-sa-20170322-xeci)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by an command injection
vulnerability due to insufficient validation of user-supplied HTTP
input parameters. An authenticated, remote attacker can exploit this
issue, via a specially crafted request, to execute arbitrary commands
with root level privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-xeci
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33e0fa8b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy83069");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy83069.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
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

if (ver == "16.2.1") flag = 1;

cmds = make_list();
# Confirm whether a device is listening on the DHCP server port
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  pat = "HTTP server status:\s+Enabled";

  buf = cisco_command_kb_item("Host/Cisco/Config/show ip http server status", "show ip http server status");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:pat, string:buf, icase:TRUE))
    {
      cmds = make_list(cmds, "show ip http server status");
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
    bug_id   : "CSCuy83069",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
