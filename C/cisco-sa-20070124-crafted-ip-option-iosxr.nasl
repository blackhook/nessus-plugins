#TRUSTED 9d0b5a99835d470236976b1a581e318963362164c8441bbce9c7031aa169dcb3a4c01b8b60736d85fe6828cbe7fe9bb3dac4beed81e633cbf40c59e9a0ffe7ca590ed3d546ab600ff4daaf23b325ee4f6d6281ec22d69ed382ea631d2668ef6bdf128f253b32e41ca2174254c57cc4a29e5e5fc06ffee492538477b03b0f4bd218f4fea9a29dea30da0adee232563be830c252d7145ce9129818730559de63d0af69a350fd64585df29c7861d37361d5ee545273bbccb25db9fac0c5b64fadfb7483da240f3094971521888888283d30b35acdf93980d047ba3d09e0b862ac2fddce3568b9a0a3a0f8d9d4276ece607a4e29837bcd4c461adc5c87f8a014b76969455d2bc5997ac6ac830e2579f42764b90c1ca275db6138c1bea551b1c4a7e4617b6d80e2eaf06ded73c3f6219c2851fd4c6165a18794e45fde2645b9887e23d3611dcdc47615f281bf9752bb40b171b1e9dee99099e9b9754d6ed52caf77e4d8f76550a28d7d12a2b6e5e1ae30c1522ebe3180b7a894fcaeed996a9659f3daea503a9828a13cf77fcd291565c992cde1e27c02310fddf688fbc7414fd4f40dd226dfe74b5912e76e867d6853b8fcad79ac77d59e62c7bd54541ec9c9fb688d2be536316f7df780021edf838f6adfa53d908cf6343900da2f67471bbd97738ea6a2944cffdf6d0d7a46b80a8c9636cfd96149c1e220100dc19c17a4b12f95c7
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/csa/cisco-sa-20070124-crafted-ip-option.html
#

include("compat.inc");

if (description)
{
  script_id(71431);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2007-0480");
  script_bugtraq_id(22211);
  script_xref(name:"CERT", value:"341288");
  script_xref(name:"CISCO-BUG-ID", value:"CSCeh52410");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20070124-crafted-ip-option");

  script_name(english:"Crafted IP Option Vulnerability (cisco-sa-20070124-crafted-ip-option)");
  script_summary(english:"Checks IOS XR version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco routers and switches running Cisco IOS XR software may be
vulnerable to a remotely exploitable crafted IP option Denial of Service
(DoS) attack.  Exploitation of the vulnerability may potentially allow
for arbitrary code execution.  The vulnerability may be exploited after
processing an Internet Control Message Protocol (ICMP) packet, Protocol
Independent Multicast version 2 (PIMv2) packet, Pragmatic General
Multicast (PGM) packet, or URL Rendezvous Directory (URD) packet
containing a specific crafted IP option in the packet\'s IP header.  No
other IP protocols are affected by this issue.  Cisco has made free
software available to address this vulnerability for affected
customers.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20070124-crafted-ip-option
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccd26374");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070124-crafted-ip-option.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-0480");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2013-2021 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report = "";
cbi = "CSCeh52410";
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if ((cisco_gen_ver_compare(a:version, b:"3.2.82.3") >= 0) && (cisco_gen_ver_compare(a:version, b:"3.3") == -1)) flag ++;
fixed_ver = "upgrade to 3.3.0.2 or later";

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory_all", "show inventory all");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"CRS-1", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv4_interface", "show ipv4 interface");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"protocol is Up", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed Release : ' + version +
    '\n    Fixed Release     : ' + fixed_ver + '\n';

  security_hole(port:port, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

