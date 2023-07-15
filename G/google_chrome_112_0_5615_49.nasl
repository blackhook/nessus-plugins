#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173836);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2023-1810",
    "CVE-2023-1811",
    "CVE-2023-1812",
    "CVE-2023-1813",
    "CVE-2023-1814",
    "CVE-2023-1815",
    "CVE-2023-1816",
    "CVE-2023-1817",
    "CVE-2023-1818",
    "CVE-2023-1819",
    "CVE-2023-1820",
    "CVE-2023-1821",
    "CVE-2023-1822",
    "CVE-2023-1823"
  );
  script_xref(name:"IAVA", value:"2023-A-0173-S");

  script_name(english:"Google Chrome < 112.0.5615.49 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 112.0.5615.49. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2023_04_stable-channel-update-for-desktop advisory.

  - Heap buffer overflow in Visuals. (CVE-2023-1810)

  - Use after free in Frames. (CVE-2023-1811)

  - Out of bounds memory access in DOM Bindings. (CVE-2023-1812)

  - Inappropriate implementation in Extensions. (CVE-2023-1813)

  - Insufficient validation of untrusted input in Safe Browsing. (CVE-2023-1814)

  - Use after free in Networking APIs. (CVE-2023-1815)

  - Incorrect security UI in Picture In Picture. (CVE-2023-1816)

  - Insufficient policy enforcement in Intents. (CVE-2023-1817)

  - Use after free in Vulkan. (CVE-2023-1818)

  - Out of bounds read in Accessibility. (CVE-2023-1819)

  - Heap buffer overflow in Browser History. (CVE-2023-1820)

  - Inappropriate implementation in WebShare. (CVE-2023-1821)

  - Incorrect security UI in Navigation. (CVE-2023-1822)

  - Inappropriate implementation in FedCM. (CVE-2023-1823)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/04/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b724610b");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1414018");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1420510");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1418224");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1423258");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1417325");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1278708");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1413919");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1418061");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1223346");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1406588");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1408120");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1413618");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1066555");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1406900");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 112.0.5615.49 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1818");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-1820");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/04");

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

google_chrome_check_version(installs:installs, fix:'112.0.5615.49', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
