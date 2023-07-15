#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155017);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/12");

  script_cve_id("CVE-2021-31848", "CVE-2021-31849");
  script_xref(name:"MCAFEE-SB", value:"SB10371");
  script_xref(name:"IAVA", value:"2021-A-0550");

  script_name(english:"McAfee Data Loss Prevention ePO extension Multiple Vulnerabilities (SB10371)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee ePolicy Orchestrator that is affected by multiple vulnerabilities, as
follows:

  - Cross site scripting (XSS) vulnerability in McAfee Data Loss Prevention (DLP) ePO extension prior to
    11.7.100 allows a remote attacker to highjack an active DLP ePO administrator session by convincing the
    logged in administrator to click on a carefully crafted link in the case management part of the DLP ePO
    extension. (CVE-2021-31848)

  - SQL injection vulnerability in McAfee Data Loss Prevention (DLP) ePO extension prior to 11.7.100 allows a
    remote attacker logged into ePO as an administrator to inject arbitrary SQL into the ePO database through
    the user management section of the DLP ePO extension. (CVE-2021-31849)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10371");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 11.6.400, 11.7.100, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31849");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_dlp_epo_extension_installed.nbin");
  script_require_keys("installed_sw/McAfee DLP ePO Extension", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee DLP ePO Extension', win_local:TRUE);

var constraints = [
  { 'fixed_version':'11.6.400'},
  { 'min_version':'11.7', 'fixed_version':'11.7.100' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE, 'sqli':TRUE}
);

