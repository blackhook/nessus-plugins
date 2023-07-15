#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101113);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-8613");
  script_bugtraq_id(99294);

  script_name(english:"Microsoft Security Advisory 4033453: Vulnerability in Azure AD Connect Could Allow Elevation of Privilege");
  script_summary(english:"Checks the template files for the changes.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an
elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Azure Active Directory (AD) Connect installed on the
remote Windows host is prior to 1.1.553.0, and the password writeback
setting is enabled. It is, therefore, affected by an elevation of
privilege vulnerability due to improper permissions being granted when
enabling the password writeback setting. An authenticated, remote
attacker can exploit this to reset users' passwords and gain access to
arbitrary on-premises AD privileged user accounts.

Note that Nessus did not verify if the reset password permission was
granted to on-premises AD user accounts.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2017/4033453");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Azure AD Connect version 1.1.553.0 or later. Alternatively,
apply the mitigation steps listed in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:azure_active_directory_connect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_ad_connect_installed.nbin");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Microsoft Azure AD Connect";
vuln = FALSE;

install = get_single_install(app_name:app);
version = install['version'];

if (ver_compare(ver:version, fix:"1.1.553.0", strict:FALSE) < 0)
  vuln = TRUE;

hotfix_check_fversion_init();
path = hotfix_get_systemdrive(as_dir:TRUE);

# Check for the password writeback setting.
file = hotfix_get_file_contents(path:path + "ProgramData\AADConnect\PersistedState.xml");

hotfix_handle_error(error_code:file['error'],
                    file:path + "ProgramData\AADConnect\PersistedState.xml",
                    appname:app,
                    exit_on_fail:TRUE);

hotfix_check_fversion_end();
match = pregmatch(pattern:"<Key>IAadSyncContext.EnablePasswordWriteBack<\/Key>\s*<Value>([^<]+)<\/Value>", string:file['data']);

if(match[1] == "True") writeback_enabled = TRUE;
else writeback_enabled = FALSE;

# if vuln version & writeback is enabled, or vuln version & paranoid
if ( vuln && ( writeback_enabled || report_paranoia > 1 ) )
{
  report += '\nInstalled version : ' + version;
  report += '\nFixed version     : 1.1.553.0\n';
  port = kb_smb_transport();
  security_report_v4(port:port, severity: SECURITY_WARNING, extra:report);
}
else audit(AUDIT_HOST_NOT, "affected");
