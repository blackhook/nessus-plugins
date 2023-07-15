##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143116);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-7331", "CVE-2020-7332", "CVE-2020-7333");
  script_xref(name:"MCAFEE-SB", value:"SB10335");
  script_xref(name:"IAVA", value:"2020-A-0536-S");

  script_name(english:"McAfee Endpoint Security for Windows 10.6.1 / 10.7.0 September 2020 Update < 10.6.1 / 10.7.1 November 2020 Update Multiple Vulnerabilities (SB10335)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Endpoint Security (ENS) for Windows installed on the remote Windows host is affected by
multiple vulnerabilities, as follows:

  - Cross site scripting vulnerability in the firewall ePO extension of McAfee Endpoint Security (ENS) prior
    to 10.7.0 November 2020 Update allows administrators to inject arbitrary web script or HTML via the
    configuration wizard. (CVE-2020-7333)

  - Cross Site Request Forgery vulnerability in the firewall ePO extension of McAfee Endpoint Security (ENS)
    prior to 10.7.0 November 2020 Update allows an attacker to execute arbitrary HTML code due to incorrect
    security configuration. (CVE-2020-7332)

  - Unquoted service executable path in McAfee Endpoint Security (ENS) prior to 10.7.0 November 2020 Update
    allows local users to cause a denial of service and malicious file execution via carefully crafted and
    named executable files. (CVE-2020-7331)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10335");
  script_set_attribute(attribute:"solution", value:
"Apply the 10.7.0 or 10.6.1 November 2020 Update or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7332");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:endpoint_security");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_endpoint_security_installed.nbin");
  script_require_keys("installed_sw/McAfee Endpoint Security Platform", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'McAfee Endpoint Security Platform', win_local:TRUE);

if (app_info['version'] !~ "^10\.6\.1" && app_info['version'] !~ "^10\.7\.0")
  audit(AUDIT_HOST_NOT, 'an affected version');

# Build numbers: https://kc.mcafee.com/corporate/index?page=content&id=KB82761, use "Common Client"
constraints = [
  { 'min_version':'10.6.1.2113', 'fixed_version':'10.6.1.2182', 'fixed_display':'ENS 10.6.1 November 2020 Update' },
  { 'min_version':'10.7.0.2000', 'fixed_version':'10.7.0.2174', 'fixed_display':'ENS 10.7.0 November 2020 Update' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE, xsrf:TRUE}
);
