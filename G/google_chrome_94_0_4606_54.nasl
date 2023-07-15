#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153515);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-37956",
    "CVE-2021-37957",
    "CVE-2021-37958",
    "CVE-2021-37959",
    "CVE-2021-37961",
    "CVE-2021-37962",
    "CVE-2021-37963",
    "CVE-2021-37964",
    "CVE-2021-37965",
    "CVE-2021-37966",
    "CVE-2021-37967",
    "CVE-2021-37968",
    "CVE-2021-37969",
    "CVE-2021-37970",
    "CVE-2021-37971",
    "CVE-2021-37972"
  );
  script_xref(name:"IAVA", value:"2021-A-0438-S");

  script_name(english:"Google Chrome < 94.0.4606.54 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 94.0.4606.54. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_09_stable-channel-update-for-desktop_21 advisory.

  - Use after free in File System API in Google Chrome prior to 94.0.4606.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37970)

  - Use after free in Offline use in Google Chrome on Android prior to 94.0.4606.54 allowed a remote attacker
    who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-37956)

  - Use after free in WebGPU in Google Chrome prior to 94.0.4606.54 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-37957)

  - Inappropriate implementation in Navigation in Google Chrome on Windows prior to 94.0.4606.54 allowed a
    remote attacker to inject scripts or HTML into a privileged page via a crafted HTML page. (CVE-2021-37958)

  - Use after free in Task Manager in Google Chrome prior to 94.0.4606.54 allowed an attacker who convinced a
    user to enage in a series of user gestures to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-37959)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2021/09/stable-channel-update-for-desktop_21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9293f232");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1243117");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1242269");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1223290");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1229625");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1247196");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1228557");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1231933");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1199865");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1203612");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1239709");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1238944");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1243622");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1245053");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1245879");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1248030");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1219354");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1234259");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 94.0.4606.54 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37972");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/21");

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

google_chrome_check_version(installs:installs, fix:'94.0.4606.54', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
