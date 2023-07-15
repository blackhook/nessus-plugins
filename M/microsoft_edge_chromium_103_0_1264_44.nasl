##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162624);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-33680");

  script_name(english:"Microsoft Edge (Chromium) < 103.0.1264.44 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 103.0.1264.44. It is, therefore, affected
by a vulnerability as referenced in the June 30, 2022 advisory.

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-30192, CVE-2022-33638, CVE-2022-33639. (CVE-2022-33680)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#june-30-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83620a15");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-33680");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 103.0.1264.44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33680");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '103.0.1264.44' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
