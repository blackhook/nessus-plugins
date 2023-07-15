##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148298);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id(
    "CVE-2021-21194",
    "CVE-2021-21195",
    "CVE-2021-21196",
    "CVE-2021-21197",
    "CVE-2021-21198",
    "CVE-2021-21199"
  );
  script_xref(name:"IAVA", value:"2021-A-0152-S");

  script_name(english:"Microsoft Edge (Chromium) < 89.0.774.68 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 89.0.774.68. It is, therefore, affected
by multiple vulnerabilities as referenced in the April 1, 2021 advisory. Note that Nessus has not tested for this issue
but has instead relied only on the application's self-reported version number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#april-1-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3ce740a");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21194");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21195");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21196");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21197");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21198");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21199");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 89.0.774.68 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21199");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
constraints = [
  { 'fixed_version' : '89.0.774.68' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
