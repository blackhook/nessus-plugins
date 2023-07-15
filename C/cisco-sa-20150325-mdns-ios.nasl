#TRUSTED 191041855f2f2840dfa99246eb68b2972ad664b1279b8ed0ce24a58e107bf75598b507b23341bc927f81f95e71e10496b6882624b2a3331651f676057bd5de154a26dfc1d7bab052e954d35f078040f0cbb6fb04a230dee644adb5296e9a23d68b1ce4d2e9205db358dd4e0949b88263a6304e1e7c555278598f952c40c9e93362647a27f8e29bdc3120f2ea3ad6ea6f1d278f0826d24123d669c4631e18388703db3ed439d85899a60a05399a22aca0ecb02acef67b1bacd8543100555683316415a9d34399e61a269042b8ca8e39d89e1059bcccca2240cadcad36810d6b811984eddbdee0a60114c001f7fe5e8ce7077a1a284e42bf93eb53e3497d3784a5ca67cd1252eb7070a666e614daeaeeb5c5181491d4e4df88a914720366a26e3cfcee67cb831f7b1134ee6096b26725fc16ccdf077814ec009d97f1e10ac3bd44211e84670bd6d973c5e5ffa5cde644a5b0c5cbf965306007376443e7b85d39027e34771ccdf95ab4d3c26408e5c4e6241fc325df17362a4844d9dad5ba3265181d0ab56257e16d3f4180d9cd68ce4aa32e754dfb9081d57329cae736a44cfe1a3288a15a40022cffe3f4e9889716a721233471c5d0c764f173a9dc236ab6a298bc6b547f99ca0e9078fb6f885a2b3d9ad22922079804a12a388888c664e8fd24f6e7dc5e385dc328e6609e4725fcf6c3ccd52238f896495a876522539a0e73f4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82572);
  script_version("1.15");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0650");
  script_bugtraq_id(73335);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup70579");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-mdns");

  script_name(english:"Cisco IOS Software mDNS Gateway DoS");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS software
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

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
flag = 0;
override = 0;

# Per advisory:
versions = make_list(
  "12.2IRD",
  "12.2(33)IRD1",
  "12.2IRE",
  "12.2(33)IRE3",
  "12.2SQ",
  "12.2(44)SQ1",
  "12.2SXI",
  "12.2(33)SXI4b",
  "12.4JAM",
  "12.4(25e)JAM1",
  "12.4JAP",
  "12.4(25e)JAP1m",
  "12.4JAZ",
  "12.4(25e)JAZ1",
  "15.0ED",
  "15.0(2)ED1",
  "15.1SY",
  "15.1(2)SY",
  "15.1(2)SY1",
  "15.1(2)SY2",
  "15.1(2)SY3",
  "15.2E",
  "15.2(1)E",
  "15.2(1)E1",
  "15.2(1)E2",
  "15.2(1)E3",
  "15.2(2)E",
  "15.2EX",
  "15.2(1)EX",
  "15.2JB",
  "15.2(2)JB1",
  "15.3JA",
  "15.3(3)JA1n",
  "15.3JAB",
  "15.3(3)JAB1",
  "15.3JN",
  "15.3(3)JN",
  "15.3JNB",
  "15.3(3)JNB",
  "15.3S",
  "15.3(2)S2",
  "15.3(3)S",
  "15.3(3)S1",
  "15.3(3)S1a",
  "15.3(3)S2",
  "15.3(3)S2a",
  "15.3(3)S3",
  "15.4M",
  "15.4(3)M",
  "15.4(3)M1",
  "15.4(3)M2",
  "15.4S",
  "15.4(1)S",
  "15.4(1)S1",
  "15.4(1)S2",
  "15.4(2)S",
  "15.4(2)S1",
  "15.4(3)S",
  "15.4SN",
  "15.4(2)SN",
  "15.4(2)SN1",
  "15.4(3)SN",
  "15.4(3)SN1",
  "15.4T",
  "15.4(1)T",
  "15.4(1)T1",
  "15.4(1)T2",
  "15.4(2)T",
  "15.4(2)T1"
);

foreach ver (versions)
{
  if (ver == version)
  {
    flag++;
    break;
  }
}

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
