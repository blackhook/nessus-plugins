#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164638);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id(
    "CVE-2022-3038",
    "CVE-2022-3039",
    "CVE-2022-3040",
    "CVE-2022-3041",
    "CVE-2022-3044",
    "CVE-2022-3045",
    "CVE-2022-3046",
    "CVE-2022-3047",
    "CVE-2022-3053",
    "CVE-2022-3054",
    "CVE-2022-3055",
    "CVE-2022-3056",
    "CVE-2022-3057",
    "CVE-2022-3058",
    "CVE-2022-38012"
  );
  script_xref(name:"IAVA", value:"2022-A-0361-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Microsoft Edge (Chromium) < 105.0.1343.25 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 105.0.1343.25. It is, therefore, affected
by multiple vulnerabilities as referenced in the September 1, 2022 advisory.

  - Use after free in Network Service. (CVE-2022-3038)

  - Use after free in WebSQL. (CVE-2022-3039, CVE-2022-3041)

  - Use after free in Layout. (CVE-2022-3040)

  - Inappropriate implementation in Site Isolation. (CVE-2022-3044)

  - Insufficient validation of untrusted input in V8. (CVE-2022-3045)

  - Use after free in Browser Tag. (CVE-2022-3046)

  - Insufficient policy enforcement in Extensions API. (CVE-2022-3047)

  - Inappropriate implementation in Pointer Lock. (CVE-2022-3053)

  - Insufficient policy enforcement in DevTools. (CVE-2022-3054)

  - Use after free in Passwords. (CVE-2022-3055)

  - Insufficient policy enforcement in Content Security Policy. (CVE-2022-3056)

  - Inappropriate implementation in iframe Sandbox. (CVE-2022-3057)

  - Use after free in Sign-In Flow. (CVE-2022-3058)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#september-1-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31d28038");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3038");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3039");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3040");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3041");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3044");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3045");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3046");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3047");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3053");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3054");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3055");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3056");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3057");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-3058");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-38012");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 105.0.1343.25 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38012");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3058");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'fixed_version' : '105.0.1343.25' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
