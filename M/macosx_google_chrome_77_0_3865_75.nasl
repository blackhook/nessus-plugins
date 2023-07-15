#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128740);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2019-5870",
    "CVE-2019-5871",
    "CVE-2019-5872",
    "CVE-2019-5873",
    "CVE-2019-5874",
    "CVE-2019-5875",
    "CVE-2019-5876",
    "CVE-2019-5877",
    "CVE-2019-5878",
    "CVE-2019-5879",
    "CVE-2019-5880",
    "CVE-2019-5881",
    "CVE-2019-13659",
    "CVE-2019-13660",
    "CVE-2019-13661",
    "CVE-2019-13662",
    "CVE-2019-13663",
    "CVE-2019-13664",
    "CVE-2019-13665",
    "CVE-2019-13666",
    "CVE-2019-13667",
    "CVE-2019-13668",
    "CVE-2019-13669",
    "CVE-2019-13670",
    "CVE-2019-13671",
    "CVE-2019-13673",
    "CVE-2019-13674",
    "CVE-2019-13675",
    "CVE-2019-13676",
    "CVE-2019-13677",
    "CVE-2019-13678",
    "CVE-2019-13679",
    "CVE-2019-13680",
    "CVE-2019-13681",
    "CVE-2019-13682",
    "CVE-2019-13683",
    "CVE-2019-13692"
  );

  script_name(english:"Google Chrome < 77.0.3865.75 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 77.0.3865.75. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2019_09_stable-channel-update-for-desktop advisory. Note that Nessus has
not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2019/09/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cdaad61");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/999311");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/990570");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/981492");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/989497");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/989797");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/979443");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/997190");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/999310");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1000217");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/986043");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/831725");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/980816");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/868846");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/882363");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/882812");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/967780");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/863661");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/915538");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/959640");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/960305");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/973056");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/986393");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/968451");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/980891");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/696454");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/997925");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/896533");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/929578");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/875178");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/939108");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/946633");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/968914");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/969684");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/970378");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/971917");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/987502");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1002279");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 77.0.3865.75 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5878");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5870");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'77.0.3865.75', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
