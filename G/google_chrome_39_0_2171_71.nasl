#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79578);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id("CVE-2014-8439");
  script_bugtraq_id(71289);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Google Chrome < 39.0.2171.71 Flash Player Remote Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 39.0.2171.71. It is, therefore, affected by a remote code
execution vulnerability in the included Flash Player plugin, which is
due to the processing of a dereferenced memory pointer.");
  # http://googlechromereleases.blogspot.com/2014/11/stable-channel-update_25.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bb46c17");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 39.0.2171.71 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8439");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'39.0.2171.71', severity:SECURITY_HOLE, xss:FALSE);
