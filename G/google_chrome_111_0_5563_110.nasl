#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173059);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2023-1528",
    "CVE-2023-1529",
    "CVE-2023-1530",
    "CVE-2023-1531",
    "CVE-2023-1532",
    "CVE-2023-1533",
    "CVE-2023-1534"
  );
  script_xref(name:"IAVA", value:"2023-A-0154-S");

  script_name(english:"Google Chrome < 111.0.5563.110 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 111.0.5563.110. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2023_03_stable-channel-update-for-desktop_21 advisory.

  - Use after free in Passwords. (CVE-2023-1528)

  - Out of bounds memory access in WebHID. (CVE-2023-1529)

  - Use after free in PDF. (CVE-2023-1530)

  - Use after free in ANGLE. (CVE-2023-1531)

  - Out of bounds read in GPU Video. (CVE-2023-1532)

  - Use after free in WebProtect. (CVE-2023-1533)

  - Out of bounds read in ANGLE. (CVE-2023-1534)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/03/stable-channel-update-for-desktop_21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa3eba7d");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1421773");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1419718");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1419831");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1415330");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1421268");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1422183");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1422594");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 111.0.5563.110 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1533");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-1529");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
var installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'111.0.5563.110', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
