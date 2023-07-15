#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88681);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-1622",
    "CVE-2016-1623",
    "CVE-2016-1624",
    "CVE-2016-1625",
    "CVE-2016-1626",
    "CVE-2016-1627"
  );

  script_name(english:"Google Chrome < 48.0.2564.109 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 48.0.2564.109. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the Extensions component
    that allows an attacker to bypass the same-origin
    policy. No other details are available from the vendor.
    (CVE-2016-1622)

  - An unspecified flaw exists in the DOM component that
    allows an attacker to bypass the same-origin policy. No
    other details are available from the vendor.
    (CVE-2016-1623)

  - An overflow condition condition exists in the Brotli
    component due to improper validation of user-supplied
    input. An attacker can exploit this to execute arbitrary
    code. (CVE-2016-1624)

  - An unspecified flaw exists in the Chrome Instant
    component that allows an attacker to bypass navigation.
    No other details are available from the vendor.
    (CVE-2016-1625)

  - An out-of-bounds read error exists in Google PDFium that
    allows an attacker to crash a process linked against the
    library or to disclose memory contents. (CVE-2016-1626)

  - Multiple flaws exist that allow an attacker to have an
    unspecified impact. No other details are available from
    the vendor. (CVE-2016-1627)");
  # http://googlechromereleases.blogspot.com/2016/02/stable-channel-update_9.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ee83f82");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 48.0.2564.109 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1627");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'48.0.2564.109', severity:SECURITY_WARNING);
