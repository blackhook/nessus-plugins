#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80951);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2014-7923",
    "CVE-2014-7924",
    "CVE-2014-7925",
    "CVE-2014-7926",
    "CVE-2014-7927",
    "CVE-2014-7928",
    "CVE-2014-7929",
    "CVE-2014-7930",
    "CVE-2014-7931",
    "CVE-2014-7932",
    "CVE-2014-7933",
    "CVE-2014-7934",
    "CVE-2014-7935",
    "CVE-2014-7936",
    "CVE-2014-7937",
    "CVE-2014-7938",
    "CVE-2014-7939",
    "CVE-2014-7940",
    "CVE-2014-7941",
    "CVE-2014-7942",
    "CVE-2014-7943",
    "CVE-2014-7944",
    "CVE-2014-7945",
    "CVE-2014-7946",
    "CVE-2014-7947",
    "CVE-2014-7948",
    "CVE-2015-1205",
    "CVE-2015-1346",
    "CVE-2015-1359",
    "CVE-2015-1360"
  );
  script_bugtraq_id(
    72288,
    72858,
    73076,
    73077
  );

  script_name(english:"Google Chrome < 40.0.2214.91 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is a
version prior to 40.0.2214.91. It is, therefore, affected by
vulnerabilities in the following components :

  - AppCache
  - DOM
  - FFmpeg
  - Fonts
  - ICU
  - IndexedDB
  - PDFium
  - Skia
  - Speech
  - UI
  - V8
  - Views
  - WebAudio");
  script_set_attribute(attribute:"see_also", value:"http://googlechromereleases.blogspot.com/2015/01/stable-update.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 40.0.2214.91 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1360");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'40.0.2214.91', severity:SECURITY_HOLE, xss:FALSE);
