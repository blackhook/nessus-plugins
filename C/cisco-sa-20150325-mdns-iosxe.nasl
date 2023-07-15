#TRUSTED 46ed426ef1dbe2891c9ca883a6b275bc75ca958004803e31bcec37da9eba696f25a2ac9491cf453a9679c78c3281bf5d44cc6ecc8e565753466e81b9fde2d70f92ab252276c848286ebf30c5415de7177412a45bbba20408d3ca82c321b22ec52ec45ddc137b9de59e6fd66447322dba90fbd93be14f2e4b66330a14fb7e8f0625ee425ef0c7b5ae83c9eebf98c3d221cf0faeca72aa15008633f55d5813e21d6c5d74dc2cdd744805bbf75b60c59832a8b1809101a21aaec6af252440a9bc71f359994c8170330fd73f6271541c2c7e21c89a5e5aac45ce93b064472e79cbdaa68525a99f65b4b4074dc74f48d4f41e8e50717f6295e77081c7cc09b87b32150f4b23621df536de7b1ddbeae6170eb9aa12be6abdf0e908750a9f078b56b4825053acfdd2bfc1504c6226da73f68532cbee16df4cac947a0d6d788bfae14457f82b847da9946575f66899103b424c76b13b41bac9db7cc0139f53b029e531674b027ae817f080959c87cf803b8988de5715715125c4559369490df01a254610354bc082f3a808e31010a1952c7a8fbecd34f013313448720f4bc2586171c84209992f15b4f23e7716c278d22f73254543cf9c04239713d4c30f095fc2b07072bb667ef78c8c546c0e61bf04542261c6bf4c1d1e1def7ed78d25afcb8d41b411709db0bdea2dab887095893bb32405f0513ffbecd2cbdea79641a3e9f22996ee
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82573);
  script_version("1.15");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0650");
  script_bugtraq_id(73335);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup70579");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-mdns");

  script_name(english:"Cisco IOS XE Software mDNS Gateway DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XE software
that is affected by a vulnerability in the multicast DNS gateway
component due to improper validation of mDNS packets. A remote,
unauthenticated attacker, by sending crafted packets to UDP port 5353,
can exploit this to cause a device reload, leading to a denial of
service.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCup70579");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-mdns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a10c73d");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37820");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCup70579.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
flag = 0;
override = 0;

if (
  version =~ "^3.3.[01]SE$" ||
  version =~ "^3.5.[0-3]E$" ||
  version =~ "^3.6.0E$" ||
  version =~ "^3.10.([0123]|1x[bc]|2a)S$" ||
  version =~ "^3.11.[012]S$" ||
  version =~ "^3.12.[01]S$" ||
  version =~ "^3.13.0a?S$"
) flag++;

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_socket",
                              "show ip socket");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+5353\s", string:buf))
      flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag++;
    override++;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCup70579' +
    '\n  Installed release : ' + version +
    '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
