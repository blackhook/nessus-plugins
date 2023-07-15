#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158935);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-0971",
    "CVE-2022-0972",
    "CVE-2022-0973",
    "CVE-2022-0974",
    "CVE-2022-0975",
    "CVE-2022-0976",
    "CVE-2022-0977",
    "CVE-2022-0978",
    "CVE-2022-0979",
    "CVE-2022-0980"
  );
  script_xref(name:"IAVA", value:"2022-A-0120-S");

  script_name(english:"Google Chrome < 99.0.4844.74 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 99.0.4844.74. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2022_03_stable-channel-update-for-desktop_15 advisory.

  - Use after free in New Tab Page in Google Chrome prior to 99.0.4844.74 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via specific user
    interactions. (CVE-2022-0980)

  - Use after free in Blink Layout in Google Chrome on Android prior to 99.0.4844.74 allowed a remote attacker
    who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2022-0971)

  - Use after free in Extensions in Google Chrome prior to 99.0.4844.74 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2022-0972)

  - Use after free in Safe Browsing in Google Chrome prior to 99.0.4844.74 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0973)

  - Use after free in Splitscreen in Google Chrome on Chrome OS prior to 99.0.4844.74 allowed a remote
    attacker who convinced a user to engage in specific user interaction to potentially exploit heap
    corruption via a crafted HTML page. (CVE-2022-0974)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/03/stable-channel-update-for-desktop_15.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43ad24da");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1299422");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1301320");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1297498");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1291986");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1295411");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1296866");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1299225");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1299264");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1302644");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1302157");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 99.0.4844.74 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0980");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0977");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/15");

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

google_chrome_check_version(fix:'99.0.4844.74', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
