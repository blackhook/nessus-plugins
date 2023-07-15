#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155601);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2021-26436",
    "CVE-2021-26439",
    "CVE-2021-30606",
    "CVE-2021-30607",
    "CVE-2021-30608",
    "CVE-2021-30609",
    "CVE-2021-30610",
    "CVE-2021-30611",
    "CVE-2021-30612",
    "CVE-2021-30613",
    "CVE-2021-30614",
    "CVE-2021-30615",
    "CVE-2021-30616",
    "CVE-2021-30617",
    "CVE-2021-30618",
    "CVE-2021-30619",
    "CVE-2021-30620",
    "CVE-2021-30621",
    "CVE-2021-30622",
    "CVE-2021-30623",
    "CVE-2021-30624",
    "CVE-2021-36930",
    "CVE-2021-38641",
    "CVE-2021-38642"
  );
  script_xref(name:"IAVA", value:"2021-A-0401-S");
  script_xref(name:"IAVA", value:"2021-A-0432-S");

  script_name(english:"Microsoft Edge (Chromium) < 93.0.961.38 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 93.0.961.38. It is, therefore, affected
by multiple vulnerabilities as referenced in the September 2, 2021 advisory.

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability This CVE ID is unique from
    CVE-2021-36930. (CVE-2021-26436)

  - Microsoft Edge for Android Information Disclosure Vulnerability (CVE-2021-26439)

  - Chromium: CVE-2021-30606 Use after free in Blink (CVE-2021-30606)

  - Chromium: CVE-2021-30607 Use after free in Permissions (CVE-2021-30607)

  - Chromium: CVE-2021-30608 Use after free in Web Share (CVE-2021-30608)

  - Chromium: CVE-2021-30609 Use after free in Sign-In (CVE-2021-30609)

  - Chromium: CVE-2021-30610 Use after free in Extensions API (CVE-2021-30610)

  - Chromium: CVE-2021-30611 Use after free in WebRTC (CVE-2021-30611)

  - Chromium: CVE-2021-30612 Use after free in WebRTC (CVE-2021-30612)

  - Chromium: CVE-2021-30613 Use after free in Base internals (CVE-2021-30613)

  - Chromium: CVE-2021-30614 Heap buffer overflow in TabStrip (CVE-2021-30614)

  - Chromium: CVE-2021-30615 Cross-origin data leak in Navigation (CVE-2021-30615)

  - Chromium: CVE-2021-30616 Use after free in Media (CVE-2021-30616)

  - Chromium: CVE-2021-30617 Policy bypass in Blink (CVE-2021-30617)

  - Chromium: CVE-2021-30618 Inappropriate implementation in DevTools (CVE-2021-30618)

  - Chromium: CVE-2021-30619 UI Spoofing in Autofill (CVE-2021-30619)

  - Chromium: CVE-2021-30620 Insufficient policy enforcement in Blink (CVE-2021-30620)

  - Chromium: CVE-2021-30621 UI Spoofing in Autofill (CVE-2021-30621)

  - Chromium: CVE-2021-30622 Use after free in WebApp Installs (CVE-2021-30622)

  - Chromium: CVE-2021-30623 Use after free in Bookmarks (CVE-2021-30623)

  - Chromium: CVE-2021-30624 Use after free in Autofill (CVE-2021-30624)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability This CVE ID is unique from
    CVE-2021-26436. (CVE-2021-36930)

  - Microsoft Edge for Android Spoofing Vulnerability (CVE-2021-38641)

  - Microsoft Edge for iOS Spoofing Vulnerability (CVE-2021-38642)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#september-2-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eab98635");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26436");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26439");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30606");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30607");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30608");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30609");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30610");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30611");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30612");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30613");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30614");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30615");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30616");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30617");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30618");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30619");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30620");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30621");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30622");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30623");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30624");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36930");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38641");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38642");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 93.0.961.38 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36930");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '93.0.961.38' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
