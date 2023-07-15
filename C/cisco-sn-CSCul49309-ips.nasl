#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73027);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id("CVE-2014-2103");
  script_bugtraq_id(65864);
  script_xref(name:"CISCO-BUG-ID", value:"CSCul49309");
  script_xref(name:"CISCO-BUG-ID", value:"CSCum52355");

  script_name(english:"Cisco IPS MainApp SNMP DoS (CSCul49309)");
  script_summary(english:"Checks the IPS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in Cisco IPS Software could allow an unauthenticated,
remote attacker to cause the MainApp to hang intermittently due to
improper handling of SNMP packets sent to the management interface. 

Note that, in order to for the remote host to be affected by this issue,
SNMP must be enabled.  Also, SNMP v3 users without the 'noAuth' option
enabled will need valid credentials to exploit this issue.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=33109
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?710f1590");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2103.html");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco Bug Id
CSCul49309.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2103");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:intrusion_prevention_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ips_version.nasl");
  script_require_keys("Host/Cisco/IPS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('Host/Cisco/IPS/Version');

if (report_paranoia < 2) get_kb_item_or_exit("SNMP/port");

if (
  version =~ "^7\.0\([12](p\d)?\)E3$" ||
  version =~ "^7\.0\([2-9](a|p\d)?\)E4$" ||
  version =~ "^7\.1\([0-8](p\d)?\)E4$" ||
  version =~ "^7\.2\(1\)(p\d)?\)E4$" ||
  version == "7.2(1)V32"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.2(2)E4' +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IPS', version);
