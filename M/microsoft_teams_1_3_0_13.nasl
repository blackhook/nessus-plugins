##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144813);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2020-17091");
  script_xref(name:"IAVA", value:"2021-A-0002");
  script_xref(name:"CEA-ID", value:"CEA-2020-0135");

  script_name(english:"Microsoft Teams < 1.3.0.13000 Remote Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The version of Microsoft Teams installed on the remote Windows host is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Teams installed on the remote Windows host is a
version prior to 1.3.0.13000. It is, therefore, affected by remote code execution
vulnerability.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17091");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Teams 1.3.0.13000 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17091");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:teams");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_teams_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Teams");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Microsoft Teams', win_local:TRUE);
constraints = [
  { 'min_version' : '1.0.0.0', 'fixed_version' : '1.3.0.13000' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
