#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84742);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-2418");
  script_xref(name:"MSKB", value:"3074162");

  script_name(english:"MS KB3074162: Vulnerability in Microsoft Malicious Software Removal Tool Could Allow Elevation of Privilege");
  script_summary(english:"Checks the version of MSRT.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an antimalware application that is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability due to the Malicious Software Removal Tool (MSRT)
failing to properly handle a race condition involving DLL-planting.
An authenticated attacker can exploit this vulnerability by placing a
specially crafted DLL file in a local directory that is later run by
MSRT, resulting in an elevation of privileges.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2015/3074162");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/2510781/microsoft-malware-protection-engine-deployment-information");
  script_set_attribute(attribute:"solution", value:
"Enable automatic updates to update the scan engine for the relevant
antimalware applications. Refer to KB2510781 for information on how to
verify MMPE (and the associated MSRT) has been updated.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2418");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:malware_protection_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_mrt_installed.nasl");
  script_require_keys("SMB/MRT/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

version = get_kb_item_or_exit('SMB/MRT/Version');
app = "Microsoft Malicious Software Removal Tool";

if (ver_compare(ver:version, fix:'5.26.0.0') == -1)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : Microsoft Malicious Software Removal Tool' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.26\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
