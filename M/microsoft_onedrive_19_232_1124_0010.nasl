#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139231);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/29");

  script_cve_id("CVE-2020-0935");
  script_xref(name:"IAVA", value:"2020-A-0151-S");

  script_name(english:"Microsoft OneDrive Elevation of Privilege (CVE-2020-0935)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft OneDrive installed on the remote Windows host is prior to 19.232.1124.0010. It is, therefore,
affected by an elevation of privilege vulnerability due to the application improperly handling symbolic links. An
authenticated, local attacker can exploit this, by running a specially crafted application to overwrite a target file,
to escalate privileges.");
  # https://support.microsoft.com/en-us/office/onedrive-release-notes-845dcf18-f921-435e-bf28-4e24b95e5fc0?ui=en-us&rs=en-us&ad=us#ID0EACAAA=Windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef9a20ca");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0935
  # Adding as reference to "per user" installs not being affected by CVE-2020-0935
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?915d679c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft OneDrive version 19.232.1124.0010 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0935");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onedrive");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_onedrive_installed.nbin");
  script_require_keys("installed_sw/Microsoft OneDrive", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Microsoft OneDrive', win_local:TRUE);

constraints = [{ 'fixed_version' : '19.232.1124.0010' }];

if (!empty_or_null(app_info) &&
    !empty_or_null(app_info["PerUserInstall"]) &&
    app_info["PerUserInstall"] == 1)
    audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft OneDrive');
else
  vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
