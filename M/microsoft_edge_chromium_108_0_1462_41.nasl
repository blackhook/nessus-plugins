#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168406);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2022-4174",
    "CVE-2022-4175",
    "CVE-2022-4177",
    "CVE-2022-4178",
    "CVE-2022-4179",
    "CVE-2022-4180",
    "CVE-2022-4181",
    "CVE-2022-4182",
    "CVE-2022-4183",
    "CVE-2022-4184",
    "CVE-2022-4185",
    "CVE-2022-4186",
    "CVE-2022-4187",
    "CVE-2022-4188",
    "CVE-2022-4189",
    "CVE-2022-4190",
    "CVE-2022-4191",
    "CVE-2022-4192",
    "CVE-2022-4193",
    "CVE-2022-4194",
    "CVE-2022-4195",
    "CVE-2022-4262",
    "CVE-2022-41115",
    "CVE-2022-44688",
    "CVE-2022-44708"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/12/26");
  script_xref(name:"IAVA", value:"2022-A-0507-S");
  script_xref(name:"IAVA", value:"2022-A-0510-S");

  script_name(english:"Microsoft Edge (Chromium) < 108.0.1462.41 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 108.0.1462.41. It is, therefore, affected
by multiple vulnerabilities as referenced in the December 5, 2022 advisory.

  - Type confusion in V8 in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-4174)

  - Use after free in Camera Capture in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4175)

  - Use after free in Extensions in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a
    user to install an extension to potentially exploit heap corruption via a crafted Chrome Extension and UI
    interaction. (Chromium security severity: High) (CVE-2022-4177)

  - Use after free in Mojo in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2022-4178)

  - Use after free in Audio in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user
    to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (Chromium security severity: High) (CVE-2022-4179)

  - Use after free in Mojo in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user to
    install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (Chromium security severity: High) (CVE-2022-4180)

  - Use after free in Forms in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-4181)

  - Inappropriate implementation in Fenced Frames in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass fenced frame restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4182)

  - Insufficient policy enforcement in Popup Blocker in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4183)

  - Insufficient policy enforcement in Autofill in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass autofill restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4184)

  - Inappropriate implementation in Navigation in Google Chrome on iOS prior to 108.0.5359.71 allowed a remote
    attacker to spoof the contents of the modal dialogue via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4185)

  - Insufficient validation of untrusted input in Downloads in Google Chrome prior to 108.0.5359.71 allowed an
    attacker who convinced a user to install a malicious extension to bypass Downloads restrictions via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2022-4186)

  - Insufficient policy enforcement in DevTools in Google Chrome on Windows prior to 108.0.5359.71 allowed a
    remote attacker to bypass filesystem restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4187)

  - Insufficient validation of untrusted input in CORS in Google Chrome on Android prior to 108.0.5359.71
    allowed a remote attacker to bypass same origin policy via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2022-4188)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 108.0.5359.71 allowed an attacker
    who convinced a user to install a malicious extension to bypass navigation restrictions via a crafted
    Chrome Extension. (Chromium security severity: Medium) (CVE-2022-4189)

  - Insufficient data validation in Directory in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4190)

  - Use after free in Sign-In in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who convinced
    a user to engage in specific UI interaction to potentially exploit heap corruption via profile
    destruction. (Chromium security severity: Medium) (CVE-2022-4191)

  - Use after free in Live Caption in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via UI
    interaction. (Chromium security severity: Medium) (CVE-2022-4192)

  - Insufficient policy enforcement in File System API in Google Chrome prior to 108.0.5359.71 allowed a
    remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4193)

  - Use after free in Accessibility in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4194)

  - Insufficient policy enforcement in Safe Browsing in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass Safe Browsing warnings via a malicious file. (Chromium security severity: Medium)
    (CVE-2022-4195)

  - Type confusion in V8 in Google Chrome prior to 108.0.5359.94 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-4262)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#december-5-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26b297b9");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41115");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4174");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4175");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4177");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4178");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4179");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4180");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4181");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4182");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4183");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4184");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4185");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4186");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4187");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4188");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4189");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4190");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4191");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4192");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4193");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4194");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4195");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-4262");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-44688");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-44708");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 108.0.1462.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44708");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-4262");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
  { 'fixed_version' : '108.0.1462.41' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
