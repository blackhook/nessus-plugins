#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139744);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-7300",
    "CVE-2020-7301",
    "CVE-2020-7302",
    "CVE-2020-7303",
    "CVE-2020-7304",
    "CVE-2020-7305"
  );
  script_xref(name:"MCAFEE-SB", value:"SB10326");
  script_xref(name:"IAVA", value:"2020-A-0378");

  script_name(english:"McAfee Data Loss Prevention ePO extension Multiple Vulnerabilities (SB10326)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee ePolicy Orchestrator that is affected by multiple vulnerabilities,
including the following:

  - Unrestricted Upload of File with Dangerous Type in McAfee Data Loss Prevention (DLP) ePO extension prior
    to 11.5.3 allows authenticated attackers to upload malicious files to the DLP case management section via
    lack of sanity checking. (CVE-2020-7302)

  - Improper Authorization vulnerability in McAfee Data Loss Prevention (DLP) ePO extension prior to 11.5.3
    allows authenticated remote attackers to change the configuration when logged in with view only privileges
    via carefully constructed HTTP post messages. (CVE-2020-7300)

  - Cross Site scripting vulnerability in McAfee Data Loss Prevention (DLP) ePO extension prior to 11.5.3
    allows authenticated attackers to trigger alerts via the file upload tab in the DLP case management
    section. (CVE-2020-7301)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10326");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DLP 11.3.28, 11.4.200, 11.5.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7302");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-7304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_dlp_epo_extension_installed.nbin");
  script_require_keys("installed_sw/McAfee DLP ePO Extension", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'McAfee DLP ePO Extension', win_local:TRUE);

constraints = [
  { 'min_version':'11.3', 'fixed_version':'11.3.28', 'fixed_display':'11.5.3 / 11.4.200 / 11.3.28'},
  { 'min_version':'11.4', 'fixed_version':'11.4.200', 'fixed_display':'11.5.3 / 11.4.200' },
  { 'min_version':'11.5', 'fixed_version':'11.5.3' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE, xsrf:TRUE}
);

