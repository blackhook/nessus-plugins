#
# (C) Tenable Network Security, Inc.
#




include("compat.inc");

if (description)
{
  script_id(62393);
  script_version("1.11");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2011-3174");
  script_bugtraq_id(50576, 55267);

  script_name(english:"Flexera ISGrid ActiveX Control Remote Code Execution Vulnerabilities");
  script_summary(english:"Checks version of ActiveX Control");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by remote code
execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has the Flexera ISGrid ActiveX control installed.  The
control is affected by remote code execution vulnerabilities that can be
triggered via the 'bstrReplaceText()' and 'DoFindReplace()' methods.  By
tricking a victim into visiting a specially crafted page, an attacker
may be able to execute arbitrary code on the host.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-319/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-12-180/");
  # http://kb.flexerasoftware.com/selfservice/viewContent.do?externalId=Q201079
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f940fbc9");
  script_set_attribute(attribute:"solution", value:
"Apply the hotfix from Flexera.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3174");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:flexera:adminstudio");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:flexera:installshield");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_configuration_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

clsid = '{C03AAB45-221B-11D4-AB3A-00C04F09719C}';

if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

info = '';

fix = '18.0.0.329';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

if (ver_compare(ver:version, fix:fix) == -1)
{
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
      info += '\n  Class identifier  : ' + clsid +
              '\n  Filename          : ' + file +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : ' + fix + '\n';
   }
}

activex_end();

# Report findings.
if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Moreover, its kill bit is not set so it is accessible via Internet\n' +
      'Explorer.\n';
  }

  if (report_verbosity > 0) security_warning(port:kb_smb_transport(), extra:report);
  else security_warning(kb_smb_transport());

  exit(0);
}
else
{
  if(ver_compare(ver:version, fix:fix) >= 0)
    audit(AUDIT_INST_VER_NOT_VULN, file, version);
  else
    exit(0, "The " + file + " control is installed, but its kill bit is set.");
}
