##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161979);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-2007",
    "CVE-2022-2008",
    "CVE-2022-2010",
    "CVE-2022-2011"
  );
  script_xref(name:"IAVA", value:"2022-A-0231-S");

  script_name(english:"Google Chrome < 102.0.5005.115 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 102.0.5005.115. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_06_stable-channel-update-for-desktop advisory.

  - Use after free in ANGLE in Google Chrome prior to 102.0.5005.115 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2011)

  - Use after free in WebGPU in Google Chrome prior to 102.0.5005.115 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2007)

  - Double free in WebGL in Google Chrome prior to 102.0.5005.115 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2008)

  - Out of bounds read in compositing in Google Chrome prior to 102.0.5005.115 allowed a remote attacker who
    had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2022-2010)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/06/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?401fd0d4");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1326210");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1317673");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1325298");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1330379");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 102.0.5005.115 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2011");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2010");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/09");

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

google_chrome_check_version(installs:installs, fix:'102.0.5005.115', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
