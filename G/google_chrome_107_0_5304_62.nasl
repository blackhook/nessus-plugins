#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166468);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-3652",
    "CVE-2022-3653",
    "CVE-2022-3654",
    "CVE-2022-3655",
    "CVE-2022-3656",
    "CVE-2022-3657",
    "CVE-2022-3658",
    "CVE-2022-3659",
    "CVE-2022-3660",
    "CVE-2022-3661"
  );
  script_xref(name:"IAVA", value:"2022-A-0446-S");

  script_name(english:"Google Chrome < 107.0.5304.62 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 107.0.5304.62. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_10_stable-channel-update-for-desktop_25 advisory.

  - Use after free in Accessibility in Google Chrome on Chrome OS prior to 107.0.5304.62 allowed a remote
    attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption
    via specific UI interactions. (Chromium security severity: Medium) (CVE-2022-3659)

  - Type confusion in V8 in Google Chrome prior to 107.0.5304.62 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3652)

  - Heap buffer overflow in Vulkan in Google Chrome prior to 107.0.5304.62 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-3653)

  - Use after free in Layout in Google Chrome prior to 107.0.5304.62 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3654)

  - Heap buffer overflow in Media Galleries in Google Chrome prior to 107.0.5304.62 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2022-3655)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/10/stable-channel-update-for-desktop_25.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6eb6f5");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1369871");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1354271");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1365330");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1343384");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1345275");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1351177");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1352817");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1355560");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1327505");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1350111");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 107.0.5304.62 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3659");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
var installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'107.0.5304.62', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
