##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163274);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-2163",
    "CVE-2022-2477",
    "CVE-2022-2478",
    "CVE-2022-2479",
    "CVE-2022-2480",
    "CVE-2022-2481"
  );
  script_xref(name:"IAVA", value:"2022-A-0253-S");
  script_xref(name:"IAVA", value:"2022-A-0282-S");

  script_name(english:"Google Chrome < 103.0.5060.134 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 103.0.5060.134. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_07_stable-channel-update-for-desktop_19 advisory.

  - Use after free in Views in Google Chrome prior to 103.0.5060.134 allowed a remote attacker who convinced a
    user to engage in specific user interactions to potentially exploit heap corruption via UI interaction.
    (CVE-2022-2481)

  - Use after free in Cast UI and Toolbar in Google Chrome prior to 103.0.5060.134 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via UI
    interaction. (CVE-2022-2163)

  - Use after free in Guest View in Google Chrome prior to 103.0.5060.134 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2022-2477)

  - Use after free in PDF in Google Chrome prior to 103.0.5060.134 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2478)

  - Insufficient validation of untrusted input in File in Google Chrome on Android prior to 103.0.5060.134
    allowed an attacker who convinced a user to install a malicious app to obtain potentially sensitive
    information from internal file directories via a crafted HTML page. (CVE-2022-2479)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/07/stable-channel-update-for-desktop_19.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5848b53d");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1336266");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1335861");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1329987");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1339844");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1341603");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1308341");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 103.0.5060.134 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2481");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'103.0.5060.134', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
