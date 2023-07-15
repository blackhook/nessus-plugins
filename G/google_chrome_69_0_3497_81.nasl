#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117333);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-16065",
    "CVE-2018-16067",
    "CVE-2018-16068",
    "CVE-2018-16070",
    "CVE-2018-16071",
    "CVE-2018-16072",
    "CVE-2018-16073",
    "CVE-2018-16074",
    "CVE-2018-16075",
    "CVE-2018-16076",
    "CVE-2018-16077",
    "CVE-2018-16078",
    "CVE-2018-16079",
    "CVE-2018-16080",
    "CVE-2018-16081",
    "CVE-2018-16082",
    "CVE-2018-16083",
    "CVE-2018-16084",
    "CVE-2018-16085",
    "CVE-2018-16086",
    "CVE-2018-16087",
    "CVE-2018-16088"
  );

  script_name(english:"Google Chrome < 69.0.3497.81 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 69.0.3497.81. It is, therefore, affected by multiple
vulnerabilities as noted in Google Chrome stable channel update
release notes for 2018/09/04. Please refer to the release notes for
additional information. Note that Nessus has not attempted to exploit
these issues but has instead relied only on the application's self-
reported version number.");
  # https://chromereleases.googleblog.com/2018/09/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?424454d5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 69.0.3497.81 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16085");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'69.0.3497.81', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
