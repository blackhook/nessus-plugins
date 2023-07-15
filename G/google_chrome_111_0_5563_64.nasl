#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172221);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id(
    "CVE-2023-1213",
    "CVE-2023-1214",
    "CVE-2023-1215",
    "CVE-2023-1216",
    "CVE-2023-1217",
    "CVE-2023-1218",
    "CVE-2023-1219",
    "CVE-2023-1220",
    "CVE-2023-1221",
    "CVE-2023-1222",
    "CVE-2023-1223",
    "CVE-2023-1224",
    "CVE-2023-1225",
    "CVE-2023-1226",
    "CVE-2023-1227",
    "CVE-2023-1228",
    "CVE-2023-1229",
    "CVE-2023-1230",
    "CVE-2023-1231",
    "CVE-2023-1232",
    "CVE-2023-1233",
    "CVE-2023-1234",
    "CVE-2023-1235",
    "CVE-2023-1236"
  );
  script_xref(name:"IAVA", value:"2023-A-0123-S");

  script_name(english:"Google Chrome < 111.0.5563.64 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 111.0.5563.64. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2023_03_stable-channel-update-for-desktop advisory.

  - Use after free in Swiftshader. (CVE-2023-1213)

  - Type Confusion in V8. (CVE-2023-1214)

  - Type Confusion in CSS. (CVE-2023-1215)

  - Use after free in DevTools. (CVE-2023-1216)

  - Stack buffer overflow in Crash reporting. (CVE-2023-1217)

  - Use after free in WebRTC. (CVE-2023-1218)

  - Heap buffer overflow in Metrics. (CVE-2023-1219)

  - Heap buffer overflow in UMA. (CVE-2023-1220)

  - Insufficient policy enforcement in Extensions API. (CVE-2023-1221)

  - Heap buffer overflow in Web Audio API. (CVE-2023-1222)

  - Insufficient policy enforcement in Autofill. (CVE-2023-1223)

  - Insufficient policy enforcement in Web Payments API. (CVE-2023-1224, CVE-2023-1226)

  - Insufficient policy enforcement in Navigation. (CVE-2023-1225)

  - Use after free in Core. (CVE-2023-1227)

  - Insufficient policy enforcement in Intents. (CVE-2023-1228)

  - Inappropriate implementation in Permission prompts. (CVE-2023-1229)

  - Inappropriate implementation in WebApp Installs. (CVE-2023-1230)

  - Inappropriate implementation in Autofill. (CVE-2023-1231)

  - Insufficient policy enforcement in Resource Timing. (CVE-2023-1232, CVE-2023-1233)

  - Inappropriate implementation in Intents. (CVE-2023-1234)

  - Type Confusion in DevTools. (CVE-2023-1235)

  - Inappropriate implementation in Internals. (CVE-2023-1236)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/03/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83e395f3");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1411210");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1412487");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1417176");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1417649");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1412658");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1413628");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1415328");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1417185");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1385343");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1403515");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1398579");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1403539");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1408799");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1013080");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1348791");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1365100");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1160485");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1404230");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1274887");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1346924");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1045681");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1404621");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1404704");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1374518");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 111.0.5563.64 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1227");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/07");

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

google_chrome_check_version(installs:installs, fix:'111.0.5563.64', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
