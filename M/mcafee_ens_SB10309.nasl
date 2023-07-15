#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135972);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-7250",
    "CVE-2020-7255",
    "CVE-2020-7257",
    "CVE-2020-7259",
    "CVE-2020-7261",
    "CVE-2020-7273",
    "CVE-2020-7274",
    "CVE-2020-7275",
    "CVE-2020-7276",
    "CVE-2020-7277",
    "CVE-2020-7278"
  );
  script_xref(name:"MCAFEE-SB", value:"SB10309");
  script_xref(name:"IAVA", value:"2020-A-0171-S");

  script_name(english:"McAfee Endpoint Security for Windows 10.5.x < 10.5.5 Security Hotfix 129256 / 10.6.x < 10.6.1 April 2020 Update / 10.7.x < 10.7.0 April 2020 Update Multiple Vulnerabilities (SB10309)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Endpoint Security (ENS) for Windows installed on the remote Windows host is 10.5.x prior to
10.5.5 Security Hotfix 129256, 10.6.x prior to 10.6.1 April 2020 Update, or 10.7.x prior to 10.7.0 April 2020 
Update. It is, therefore, affected by multiple vulnerabilities:

  - A Symbolic link manipulation vulnerability in McAfee Endpoint 
    Security (ENS) for Windows prior to 10.7.0 February 2020 Update 
    allows authenticated local user to potentially gain an 
    escalation of privileges by pointing the link to files which 
    the user would not normally have permission to alter via 
    carefully creating symbolic links from the ENS log file 
    directory. (CVE-2020-7250)

  - A privilege escalation vulnerability in the administrative user 
    interface in McAfee Endpoint Security (ENS) for Windows prior to 
    10.7.0 February 2020 Update allows local users to gain elevated 
    privileges due to a configuration error.Privilege escalation 
    vulnerability in the administrative user interface in McAfee 
    Endpoint Security (ENS) for Windows prior to 10.7.0 February 
    2020 Update allows local users to gain elevated privileges 
    via a configuration error. (CVE-2020-7255)
    
  - A privilege escalation vulnerability in McAfee Endpoint Security 
    (ENS) for Windows prior to 10.7.0 February 2020 Update allows 
    local users to cause the deletion and creation of files they 
    would not normally have permission to through altering the 
    target of symbolic links whilst an anti-virus scan was in 
    progress. This is timing dependent. (CVE-2020-7257)

  It is also affected by additional vulnerabilities; see the vendor advisory for more information");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10309");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ENS 10.5.5 Security Hotfix 129256, 10.6.1 April 2020 Update, 10.7.0 April 2020 Update or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7277");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-7274");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(59, 119, 264, 269, 284, 287, 428, 693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:endpoint_security");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_endpoint_security_installed.nbin");
  script_require_keys("installed_sw/McAfee Endpoint Security Platform", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'McAfee Endpoint Security Platform', win_local:TRUE);

# release notes with version info can be found here https://kc.mcafee.com/corporate/index?page=content&id=KB82450
# however we need to drop the last octect
constraints = [
  { 'min_version':'10.5.0', 'fixed_version':'10.5.5.5182', 'fixed_display':'10.5.5.5182 (10.5.5 Security Hotfix 129256)' },
  { 'min_version':'10.6.0', 'fixed_version':'10.6.1.1936', 'fixed_display':'10.6.1.1936 (10.6.1 April 2020 Update)' },
  { 'min_version':'10.7.0', 'fixed_version':'10.7.0.1675', 'fixed_display':'10.7.0.1675 (10.7.0 April 2020 Update)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);