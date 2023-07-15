#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109915);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-0908");
  script_bugtraq_id(103112);
  script_xref(name:"IAVB", value:"2018-B-0055");

  script_name(english:"Security Update for Microsoft Identity Manager Software");
  script_summary(english:"Checks the version of Microsoft Identity Manager Software.");

  script_set_attribute(attribute:"synopsis", value:
"The versions of one or more Microsoft IDM components installed on the remote Windows 
host are affected by a cross site scripting elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of one or more Microsoft Identity Manager components
is prior to 4.4.1749.0, and is therefore affected by a cross site
scripting vulnerability which could lead to privilege escalation.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4050936/hotfix-rollup-package-build-4-4-1749-0-for-microsoft-identity-manager");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0908
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78764f50");
  script_set_attribute(attribute:"solution", value:
"Upgrade affected components to version 4.4.1749.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:identity_manager:2016:sp1");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_idm_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Microsoft IDM/installed");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::microsoft_idm::get_idm_info();

constraints = {
  "Service and Portal" : [{"min_version":"4.4.1302.0", "fixed_version":"4.4.1749.0"}],
  "Synchronization Service" : [{"min_version":"4.4.1302.0", "fixed_version":"4.4.1749.0"}],
  "Certificate Management" : [{"min_version":"4.4.1302.0", "fixed_version":"4.4.1749.0"}],
  "CM Bulk Client" : [{"min_version":"4.4.1302.0", "fixed_version":"4.4.1749.0"}],
  "CM Client" : [{"min_version":"4.4.1302.0", "fixed_version":"4.4.1749.0"}],
  "Add-ins and Extensions" : [{"min_version":"4.4.1302.0", "fixed_version":"4.4.1749.0"}]
};

vcf::microsoft_idm::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:make_array("xss",TRUE));
