#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74147);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/15 20:50:20");

  script_cve_id("CVE-2014-3273");
  script_bugtraq_id(67489);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum96282");

  script_name(english:"Cisco IOS LLDP Request Processing DoS");
  script_summary(english:"Checks IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported IOS version, the remote device may be
affected by a denial of service vulnerability related to incorrect
handling of malformed Link Layer Discovery Protocol (LLDP) packets. An
adjacent, unauthenticated attacker could exploit this issue by sending
malformed packets, causing a device reload.

Note that a successful attack requires that Channel Interface
Processor (CIP) is enabled.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34293");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34293
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?221007ad");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the bug
details for CSCum96282.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '15.2(2)TST') security_warning(0);
else if (version == '15.2(1)T1.11') security_warning(0);
else audit(AUDIT_INST_VER_NOT_VULN, 'IOS', version);
