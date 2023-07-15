#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139694);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/28");

  script_cve_id("CVE-2020-6556");
  script_xref(name:"IAVA", value:"2020-A-0382-S");

  script_name(english:"Google Chrome < 84.0.4147.135 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 84.0.4147.135. It is, therefore, affected by
a vulnerability as referenced in the 2020_08_stable-channel-update-for-desktop_18 advisory. Note that Nessus has not
tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2020/08/stable-channel-update-for-desktop_18.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32238bb2");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1115345");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 84.0.4147.135 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6556");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'84.0.4147.135', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);


