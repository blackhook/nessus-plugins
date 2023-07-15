#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157292);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2022-0452",
    "CVE-2022-0453",
    "CVE-2022-0454",
    "CVE-2022-0455",
    "CVE-2022-0456",
    "CVE-2022-0457",
    "CVE-2022-0458",
    "CVE-2022-0459",
    "CVE-2022-0460",
    "CVE-2022-0461",
    "CVE-2022-0462",
    "CVE-2022-0463",
    "CVE-2022-0464",
    "CVE-2022-0465",
    "CVE-2022-0466",
    "CVE-2022-0467",
    "CVE-2022-0468",
    "CVE-2022-0469",
    "CVE-2022-0470"
  );
  script_xref(name:"IAVA", value:"2022-A-0056-S");

  script_name(english:"Google Chrome < 98.0.4758.80 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 98.0.4758.80. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2022_02_stable-channel-update-for-desktop advisory.

  - Out of bounds memory access in V8 in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0470)

  - Use after free in Safe Browsing in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (CVE-2022-0452)

  - Use after free in Reader Mode in Google Chrome prior to 98.0.4758.80 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2022-0453)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0454)

  - Inappropriate implementation in Full Screen Mode in Google Chrome on Android prior to 98.0.4758.80 allowed
    a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-0455)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/02/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20a3576b");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1284584");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1284916");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1287962");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1270593");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1289523");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1274445");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1267060");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1244205");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1250227");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1256823");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1270470");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1268240");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1270095");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1281941");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1115460");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1239496");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1252716");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1279531");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1269225");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 98.0.4758.80 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0470");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'98.0.4758.80', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
