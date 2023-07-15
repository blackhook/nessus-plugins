#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153931);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-37977",
    "CVE-2021-37978",
    "CVE-2021-37979",
    "CVE-2021-37980"
  );
  script_xref(name:"IAVA", value:"2021-A-0459-S");

  script_name(english:"Google Chrome < 94.0.4606.81 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 94.0.4606.81. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_10_stable-channel-update-for-desktop advisory.

  - heap buffer overflow in WebRTC in Google Chrome prior to 94.0.4606.81 allowed a remote attacker who
    convinced a user to browse to a malicious website to potentially exploit heap corruption via a crafted
    HTML page. (CVE-2021-37979)

  - Use after free in Garbage Collection in Google Chrome prior to 94.0.4606.81 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37977)

  - Heap buffer overflow in Blink in Google Chrome prior to 94.0.4606.81 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37978)

  - Inappropriate implementation in Sandbox in Google Chrome prior to 94.0.4606.81 allowed a remote attacker
    to potentially bypass site isolation via Windows. (CVE-2021-37980)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2021/10/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bd0fdf5");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1252878");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1236318");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1247260");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1254631");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 94.0.4606.81 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37979");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
var installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'94.0.4606.81', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
