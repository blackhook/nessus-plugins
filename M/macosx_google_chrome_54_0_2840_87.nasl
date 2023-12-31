#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(94581);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2016-5198");
  script_bugtraq_id(94079);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Google Chrome < 54.0.2840.87 V8 Globals Stable Map Assumption Handling RCE (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS or Mac OS X
host is prior to 54.0.2840.87. It is, therefore, affected by a remote
code execution vulnerability in the V8 component due to an
out-of-bounds access error that occurs when handling stable map
assumptions for globals. An unauthenticated, remote attacker can
exploit this, via a specially crafted website, to cause a denial of
service condition or the execution of arbitrary code.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://googlechromereleases.blogspot.com/2016/11/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6e2704d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 54.0.2840.87 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5198");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'54.0.2840.87', severity:SECURITY_WARNING);
