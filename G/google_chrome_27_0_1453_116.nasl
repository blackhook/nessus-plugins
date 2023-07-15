#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66930);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-2866");

  script_name(english:"Google Chrome < 27.0.1453.116 Flash Click-Jacking");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by a click-
jacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 27.0.1453.116 and is, therefore, affected by a click-jacking
vulnerability due to the embedded Flash plugin.");
  # http://translate.google.com/translate?hl=en&sl=ru&tl=en&u=http%3A%2F%2Fhabrahabr.ru%2Fpost%2F182706%2F
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6fc9135");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/chromium/issues/detail?id=249335");
  # https://chromereleases.googleblog.com/2013/06/stable-channel-update_18.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c2cbecc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 27.0.1453.116 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'27.0.1453.116', severity:SECURITY_WARNING);
