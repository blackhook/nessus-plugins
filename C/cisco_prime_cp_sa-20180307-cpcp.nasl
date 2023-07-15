#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(107259);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");

  script_cve_id("CVE-2018-0141");
  script_bugtraq_id(103329);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc82982");
  script_xref(name:"IAVA", value:"2018-A-0083-S");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180307-cpcp");

  script_name(english:"Cisco Prime Collaboration Provisioning Hard-Coded Password Vulnerability (cisco-sa-20180307-cpcp");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management server is affected by a hard-coded
password vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Cisco Prime
Collaboration Provisioning server is 11.6. It is, therefore, affected 
by a hard-coded password vulnerability which an attacker could use to
obtain low-level privileges and subsequently escalate to root.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180307-cpcp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4474061c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Provisioning version 12.1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0141");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_provisioning");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_collaboration_provisioning_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationProvisioning/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Prime Collaboration Provisioning";
version = get_kb_item_or_exit("Host/Cisco/PrimeCollaborationProvisioning/version");

# We got the version from the WebUI and its not granular enough
# If v9, 10, 12, then we can deduce it is not vulnerable
if (version =~ "^11$")
  audit(AUDIT_VER_NOT_GRANULAR, appname, version);

fix = "12.1";

# Only one version is effected
# See cisco_prime_cp_sa-20171101-cpcp.nasl for a robust template
if (version =~ "^11\.6")
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
