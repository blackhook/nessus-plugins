#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175838);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2023-2721",
    "CVE-2023-2722",
    "CVE-2023-2723",
    "CVE-2023-2724",
    "CVE-2023-2725",
    "CVE-2023-2726"
  );
  script_xref(name:"IAVA", value:"2023-A-0260-S");
  script_xref(name:"IAVA", value:"2023-A-0265-S");

  script_name(english:"Google Chrome < 113.0.5672.126 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 113.0.5672.126. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2023_05_stable-channel-update-for-desktop_16 advisory.

  - Use after free in Navigation. (CVE-2023-2721)

  - Use after free in Autofill UI. (CVE-2023-2722)

  - Use after free in DevTools. (CVE-2023-2723)

  - Type Confusion in V8. (CVE-2023-2724)

  - Use after free in Guest View. (CVE-2023-2725)

  - Inappropriate implementation in WebApp Installs. (CVE-2023-2726)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1444360");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1400905");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1435166");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1433211");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1442516");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1442018");
  # https://chromereleases.googleblog.com/2023/05/stable-channel-update-for-desktop_16.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af1da632");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 113.0.5672.126 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2726");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'113.0.5672.126', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
