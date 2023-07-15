##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144929);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2021-1242");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv74842");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-teams-7ZMcXG99");

  script_name(english:"Cisco Webex Teams Shared File Manipulation Vulnerability (cisco-sa-webex-teams-7ZMcXG99)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-webex-teams-7ZMcXG99)");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the cisco-sa-webex-teams-7ZMcXG99 advisory. Note that Nessus has not tested for this
issue but has instead relied only on the application's self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-teams-7ZMcXG99
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10d17066");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv74842");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv74842");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1242");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(450);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_teams");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_teams_installed_win.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Webex Teams");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Webex Teams', port:port, win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);
constraints = [
  { 'fixed_version' : '40.12.0.17293' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
