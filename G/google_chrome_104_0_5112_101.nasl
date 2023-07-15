##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164155);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-2852",
    "CVE-2022-2853",
    "CVE-2022-2854",
    "CVE-2022-2855",
    "CVE-2022-2856",
    "CVE-2022-2857",
    "CVE-2022-2858",
    "CVE-2022-2859",
    "CVE-2022-2860",
    "CVE-2022-2861",
    "CVE-2022-2998"
  );
  script_xref(name:"IAVA", value:"2022-A-0332-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/08");

  script_name(english:"Google Chrome < 104.0.5112.101 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 104.0.5112.101. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_08_stable-channel-update-for-desktop_16 advisory.

  - Use after free in Chrome OS Shell in Google Chrome prior to 104.0.5112.101 allowed a remote attacker who
    convinced a user to engage in specific UI interactions to potentially exploit heap corruption via specific
    UI interactions. (CVE-2022-2859)

  - Use after free in FedCM in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2852)

  - Heap buffer overflow in Downloads in Google Chrome on Android prior to 104.0.5112.101 allowed a remote
    attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted
    HTML page. (CVE-2022-2853)

  - Use after free in SwiftShader in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-2854)

  - Use after free in ANGLE in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2855)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/08/stable-channel-update-for-desktop_16.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b4b7ba3");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1349322");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1337538");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1345042");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1338135");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1341918");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1350097");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1345630");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1338412");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1345193");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1346236");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 104.0.5112.101 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2859");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2998");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/16");

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

google_chrome_check_version(installs:installs, fix:'104.0.5112.101', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
