#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156011);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/11");

  script_cve_id(
    "CVE-2021-4052",
    "CVE-2021-4053",
    "CVE-2021-4054",
    "CVE-2021-4055",
    "CVE-2021-4056",
    "CVE-2021-4057",
    "CVE-2021-4058",
    "CVE-2021-4059",
    "CVE-2021-4061",
    "CVE-2021-4062",
    "CVE-2021-4063",
    "CVE-2021-4064",
    "CVE-2021-4065",
    "CVE-2021-4066",
    "CVE-2021-4067",
    "CVE-2021-4068"
  );

  script_name(english:"Microsoft Edge (Chromium) < 96.0.1054.53 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 96.0.1054.53. It is, therefore, affected
by multiple vulnerabilities as referenced in the December 10, 2021 advisory.

  - Use after free in window manager in Google Chrome on ChromeOS prior to 96.0.4664.93 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4067)

  - Use after free in web apps in Google Chrome prior to 96.0.4664.93 allowed an attacker who convinced a user
    to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (CVE-2021-4052)

  - Use after free in UI in Google Chrome on Linux prior to 96.0.4664.93 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4053)

  - Incorrect security UI in autofill in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    perform domain spoofing via a crafted HTML page. (CVE-2021-4054)

  - Heap buffer overflow in extensions in Google Chrome prior to 96.0.4664.93 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    Chrome Extension. (CVE-2021-4055)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#december-10-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10871512");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4052");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4053");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4054");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4055");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4056");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4057");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4058");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4059");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4061");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4062");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4063");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4064");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4065");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4066");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4067");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-4068");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 96.0.1054.53 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4067");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
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
  { 'fixed_version' : '96.0.1054.53' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
