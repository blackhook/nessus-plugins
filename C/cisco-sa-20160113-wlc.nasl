#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88103);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/20");

  script_cve_id("CVE-2015-6314");
  script_bugtraq_id(80499);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160113-wlc");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw06153");

  script_name(english:"Cisco Wireless LAN Controller Unauthorized Access Vulnerability");
  script_summary(english:"Checks the WLC version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security update.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Wireless LAN Controller (WLC) is affected by an
unauthorized access vulnerability due to an unspecified flaw. An
unauthenticated, remote attacker who can connect to the device can
exploit this to modify the device configuration, resulting in complete
compromise of the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160113-wlc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7527f49c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCuw06153, or
contact the vendor regarding patch options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6314");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Model", "Host/Cisco/WLC/Port");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/WLC/Version");
model = get_kb_item_or_exit("Host/Cisco/WLC/Model");
port = get_kb_item_or_exit("Host/Cisco/WLC/Port");


if (
  model !~ "(^|[^0-9])25\d\d($|[^0-9])" &&
  model !~ "(^|[^0-9])55\d\d($|[^0-9])" &&
  model !~ "(^|[^0-9])85\d\d($|[^0-9])" &&
  model !~ "(^|[^0-9])75\d\d($|[^0-9])" &&
  (
     model >!< "SRE" &&
    model !~ "(^|[^0-9])300($|[^0-9])" &&
    model !~ "(^|[^0-9])700($|[^0-9])" &&
    model !~ "(^|[^0-9])710($|[^0-9])" &&
    model !~ "(^|[^0-9])900($|[^0-9])" &&
    model !~ "(^|[^0-9])910($|[^0-9])"
  ) &&
  model >!< "WiSM-2"
) audit(AUDIT_HOST_NOT, "an affected model");

######################
# Known Affected :
# 7.6.120.0 or later
# 8.0 or later
# 8.1 or later
######################
# Known Fixed :
# 7.6.130.33 and higher (special escalation code)
# 8.0.120.7 and higher (special escalation code)
# 8.0.121.0
# 8.1.131.0
# 8.2.100.0 and higher
######################

fixed_version = "";
if (
  (ver_compare(ver:version, fix:"7.6.120.0", strict:FALSE) >= 0) &&
  (ver_compare(ver:version, fix:"7.6.130.33", strict:FALSE) < 0)
) fixed_version = "See solution.";
else if (
  (ver_compare(ver:version, fix:"8.0", strict:FALSE) >= 0) &&
  (ver_compare(ver:version, fix:"8.0.120.7", strict:FALSE) < 0)
) fixed_version = "8.0.121.0";
else if (
  (ver_compare(ver:version, fix:"8.1", strict:FALSE) >= 0) &&
  (ver_compare(ver:version, fix:"8.1.131.0", strict:FALSE) < 0)
) fixed_version = "8.1.131.0";
else audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Model             : ' + model +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
