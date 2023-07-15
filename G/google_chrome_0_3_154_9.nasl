#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34742);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(32258);

  script_name(english:"Google Chrome < 0.3.154.9 Address Bar Spoofing");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by an address
spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 0.3.154.9.  Such versions are reportedly affected by an address
spoofing vulnerability in pop-ups.  An attacker can leverage this
issue to manipulate a window's address bar to show a different
address than the actual origin of the content.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/498232/30/0/threaded");
  # https://chromereleases.googleblog.com/2008/10/beta-release-031549.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?632fd45d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 0.3.154.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2022 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'0.3.154.9', severity:SECURITY_WARNING);
