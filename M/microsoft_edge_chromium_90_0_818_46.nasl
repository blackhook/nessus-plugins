##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148939);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id(
    "CVE-2021-21222",
    "CVE-2021-21223",
    "CVE-2021-21224",
    "CVE-2021-21225",
    "CVE-2021-21226"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Microsoft Edge (Chromium) < 90.0.818.46 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 90.0.818.46. It is, therefore, affected
by multiple vulnerabilities as referenced in the April 22, 2021 advisory. Note that Nessus has not tested for this issue
but has instead relied only on the application's self-reported version number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#april-22-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0027f192");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21222");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21223");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21224");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21225");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21226");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 90.0.818.46 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21226");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
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
  { 'fixed_version' : '90.0.818.46' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
