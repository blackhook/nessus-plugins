##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163893);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-2603",
    "CVE-2022-2604",
    "CVE-2022-2605",
    "CVE-2022-2606",
    "CVE-2022-2610",
    "CVE-2022-2611",
    "CVE-2022-2612",
    "CVE-2022-2614",
    "CVE-2022-2615",
    "CVE-2022-2616",
    "CVE-2022-2617",
    "CVE-2022-2618",
    "CVE-2022-2619",
    "CVE-2022-2621",
    "CVE-2022-2622",
    "CVE-2022-2623",
    "CVE-2022-2624",
    "CVE-2022-33636",
    "CVE-2022-33649",
    "CVE-2022-35796"
  );

  script_name(english:"Microsoft Edge (Chromium) < 104.0.1293.47 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 104.0.1293.47. It is, therefore, affected
by multiple vulnerabilities as referenced in the August 5, 2022 advisory.

  - Use after free in Omnibox. (CVE-2022-2603)

  - Use after free in Safe Browsing. (CVE-2022-2604)

  - Out of bounds read in Dawn. (CVE-2022-2605)

  - Use after free in Managed devices API. (CVE-2022-2606)

  - Insufficient policy enforcement in Background Fetch. (CVE-2022-2610)

  - Inappropriate implementation in Fullscreen API. (CVE-2022-2611)

  - Side-channel information leakage in Keyboard input. (CVE-2022-2612)

  - Use after free in Sign-In Flow. (CVE-2022-2614)

  - Insufficient policy enforcement in Cookies. (CVE-2022-2615)

  - Inappropriate implementation in Extensions API. (CVE-2022-2616)

  - Use after free in Extensions API. (CVE-2022-2617)

  - Insufficient validation of untrusted input in Internals. (CVE-2022-2618)

  - Insufficient validation of untrusted input in Settings. (CVE-2022-2619)

  - Use after free in Extensions. (CVE-2022-2621)

  - Insufficient validation of untrusted input in Safe Browsing. (CVE-2022-2622)

  - Use after free in Offline. (CVE-2022-2623)

  - Heap buffer overflow in PDF. (CVE-2022-2624)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#august-5-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d822b1dc");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2603");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2604");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2605");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2606");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2610");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2611");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2612");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2614");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2615");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2616");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2617");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2618");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2619");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2621");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2622");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2623");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-2624");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-33636");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-33649");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-35796");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 104.0.1293.47 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2623");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-33649");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/06");

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
  { 'fixed_version' : '104.0.1293.47' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
