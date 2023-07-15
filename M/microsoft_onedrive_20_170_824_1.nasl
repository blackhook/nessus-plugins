#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140517);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id("CVE-2020-16851", "CVE-2020-16852", "CVE-2020-16853");
  script_xref(name:"IAVA", value:"2020-A-0416-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0118");

  script_name(english:"Microsoft OneDrive Multiple Elevation of Privilege");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple elevation of privilege vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft OneDrive installed on the remote Windows
host is prior to 20.170.0824.0001. It is,  therefore, affected by the
following vulnerabilities :

  - An unspecified flaw exists related to handling symbolic
    links that could allow elevation of privileges.
    (CVE-2020-16851, CVE-2020-16852, CVE-2020-16853)");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-16851
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a79e7ecd");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-16852
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f25d0b5a");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-16853
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64b60544");
  # https://support.microsoft.com/en-us/office/onedrive-release-notes-845dcf18-f921-435e-bf28-4e24b95e5fc0?ui=en-us&rs=en-us&ad=us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f37fc3f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft OneDrive version 20.170.0824.0001 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16853");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onedrive");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_onedrive_installed.nbin");
  script_require_keys("installed_sw/Microsoft OneDrive", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Microsoft OneDrive', win_local:TRUE);

constraints = [{ 'fixed_version' : '20.170.0824.0001.' }];

if (!empty_or_null(app_info) &&
    !empty_or_null(app_info["PerUserInstall"]) &&
    app_info["PerUserInstall"] == 1)
    audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft OneDrive');
else
  vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);


