#TRUSTED a4fe4cdd066edbbbd07e196a253a09e4cd8cd6ed44523588bd067756d5b6671aa36419d23d78efbaad3df21a7aba6a947e514b0b1f3b653174fd23a4daf17f34e3f9bb6c9212c5524af346e914a60196af16fb55e01b234033fe47d0aa36b2ffba64559a0045a36cdb7a81dd19b77c2b251eb9b684fa10d663c252eb2ae705974ae1a0626dce49912aa9730721a680418bf662936373a6af3b8eb8c056873fbd7ddaa68effea7f8c7f670c3ff7a74a0f8d5e211e0c029bc01e9a7c5b95684b527e50e913548818154a1a0fb11d0f1c172354b7f8ee5f7c593f5377e460bbdaf8dfa4e14b5a64b4dc0394f4c6b5d1b4bb8ee9d9f0e2a505ca23cb7ef9dad38b5479280ba8821448361ee7dfad1e4eb8110cefcf3490e9f2975ef60393ef37a4944959758a1a666a2f4388ea66e87c114446afd77013b1e0451f8cd1be7ddc358546e1c6166d8adb1b4d8bba695b6d2d69c705aa885400ae26a9ab80dd72c7a71d0814876fc3514b5dfd907a3c46b8b31e7cbf4d3d8b21bb1ed7d9f3e31befa29b2292101e723ce345eae526920d8954d868d8c9b0e55a9a734c9d322ac0e065aa0fe448514494ed3ee6af3e511a9aa9721ced4186d841c7b18ffd97bd39affddc8eaea321204f6985fad4ba994270f716ac551ae688465b2ca18e7f1caee5c0a68a7a30b5372879c1a9e67db80e613185b997e7c3ad4b3cf5f6aad6cfa9a7f7d5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76865);
  script_version("1.9");

  script_cve_id("CVE-2013-5565");
  script_bugtraq_id(63563);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj82176");

  script_name(english:"Cisco IOS XR OSPFv3 DoS (CSCuj82176)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version Cisco IOS XR software
that is affected by a denial of service vulnerability.

A denial of service flaw exists with the Open Shortest Path First
version 3 implementation when handling a type 1 link-state
advertisement packet. A remote attacker, with a malformed packet,
could crash the OSPFv3 process.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31675");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31675
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86aef271");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco Bug ID 'CSCuj82176'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5565");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/28");

  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2014-2021 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

flag = 0;

if (version == '5.1.0') flag++;
if (version == '5.1.1') flag++;

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_ospf3", "show ipv6 ospf");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"ospfv3", string:buf)) flag = 1;
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Cisco Bug ID      : CSCuj82176' +
      '\n  Installed version : ' + version +
      '\n';
    security_warning(port:port, extra:report + cisco_caveat(override));
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
