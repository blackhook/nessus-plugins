#TRUSTED a4c9cdf9548f36d227bfffb20648ef00df79a58f8ecc3f432fbeafe00a2435c995d4b8be9e456071a18a444384e5d25b88729777e0fd512b3f7b2cfacd3a340c4701b1d116b91cb89074ee05ac2d966eedd0bb0d6d4502708f5130794fc91b3b247e7a550700e490c841e0b1fbb453f4b768158bc58d6f2b3e69948bcbfd5e540938ab919ca665fd6319ee4cf04b49ba678ad209967bdaf366bd5fe60e80b82c1575a26b6d9a3ff137ff728416b44c0308feed0be6c16422832777199354be31213b18a69b636e8becbca1f0904975c538d5b307482679850db26a97c6f7d427270face3e27a6d2a21f1b27ed9566fbeb947755a7ede42bc5b4cd3ddeaaaa1322010b9510aa36e6e78bdf72f4edfebdfc02215e6c6fdda19aa811456e317200a7c68227ea82639765771253a6542a04228d3d1449b3289ec820c16c1bb7ef50c4f28fdeeb52a0af4274ec967d2b1ab2a553036eac4180c309fe3ab8d84c408259d09ed656a61e22c01178177f7c6284e26229a56049056b5958c61444aefb4669caf3fad5a4b9da05a07f20d9c158770e3ce6ad22ff632f128e44aa0075a36ab45897686e2914e389ed21e7095868a53fb6e7d0c1b1497daa000edb9677500e1090d10a6fcdd0411aaf32c5bc9cfa84cf476a1e8e8b6230d1e9a14406f352bbfc11ea982fd0b18bcc6d10057d3fa1891e7a37ddb36a748ca6a4e6b30c4e96589
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76972);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3290");
  script_bugtraq_id(68021);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun64867");

  script_name(english:"Cisco IOS XE mDNS Manipulation (CSCun64867)");
  script_summary(english:"Checks IOS XE version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a manipulation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS XE device is
affected by a manipulation vulnerability.

A flaw exists due to unconstrained autonomic networking with mDNS
(multicast Domain Name System). This could allow a remote attacker to
read or overwrite autonomic networking services.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34613");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34613
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a0809e7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCun64867.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

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

if (version == '3.12.0S') flag++;
if (version == '3.13.0S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if ("mdns" >< buf) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCun64867' +
    '\n  Installed release : ' + version;
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
