#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134701);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id(
    "CVE-2019-20503",
    "CVE-2020-6422",
    "CVE-2020-6424",
    "CVE-2020-6425",
    "CVE-2020-6426",
    "CVE-2020-6427",
    "CVE-2020-6428",
    "CVE-2020-6429",
    "CVE-2020-6449"
  );

  script_name(english:"Google Chrome < 80.0.3987.149 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 80.0.3987.149. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2020_03_stable-channel-update-for-desktop_18 advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2020/03/stable-channel-update-for-desktop_18.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7c27723");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1051748");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1031142");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1031670");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1052647");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1055788");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1057593");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1057627");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1059349");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1059686");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1057473");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 80.0.3987.149 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6449");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'80.0.3987.149', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
