#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130271);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-3652", "CVE-2019-3653", "CVE-2020-7251");
  script_xref(name:"MCAFEE-SB", value:"SB10299");
  script_xref(name:"IAVA", value:"2019-A-0396-S");

  script_name(english:"McAfee Endpoint Security for Windows 10.5.x < 10.5.5 October 2019 Update / 10.6.x < 10.6.1 February 2020 Update / 10.7.x < 10.7.0 February 2020 Update Multiple Vulnerabilities (SB10299)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Endpoint Security (ENS) for Windows installed on the remote Windows host is 10.5.x prior to
10.5.5 October 2019 Update, 10.6.x prior to 10.6.1 February 2020 Update, or 10.7.x prior to 10.7.0 February 2020 
Update. It is, therefore, affected by multiple vulnerabilities:

  - Code Injection vulnerability in EPSetup.exe in McAfee Endpoint Security (ENS) Prior to 10.6.1 October 2019
    Update allows local user to get their malicious code installed by the ENS installer via code injection into
    EPSetup.exe by an attacker with access to the installer. (CVE-2019-3652)

  - Improper access control vulnerability in Configuration tool in McAfee Endpoint Security (ENS) Prior to
    10.6.1 October 2019 Update allows local user to gain access to security configuration via unauthorized use
    of the configuration tool. (CVE-2019-3653)
    
  - Improper access control vulnerability in configuration tool in McAfee Endpoint Security (ENS) prior to
    10.6.1 February 2020 Update allows local user to disable security features via unauthorized use of the 
    configuration tool from older versions of ENS. (CVE-2020-7251)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10299");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ENS 10.5.5 October 2019 Update, 10.6.1 February 2020 Update, 10.7.0 February 2020 Update or later.

The initial fix for this issue in CVE-2019-3653 did not prevent an older version of the ESConfig Tool from modifying
the configuration for later versions. CVE-2020-7251 addresses this issue for ENS 10.6.1 and 10.7.0.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3652");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-7251");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:endpoint_security");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version':'10.5.0', 'fixed_version':'10.5.5.5290', 'fixed_display':'10.5.5.5290 (10.5.5 October 2019 Update)' },
  { 'min_version':'10.6.0', 'fixed_version':'10.6.1.1872', 'fixed_display':'10.6.1.1872 (10.6.1 February 2020 Update)' },
  { 'min_version':'10.7.0', 'fixed_version':'10.7.0.1481', 'fixed_display':'10.7.0.1481 (10.7.0 February 2020 Update)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
