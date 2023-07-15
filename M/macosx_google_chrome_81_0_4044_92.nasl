#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135400);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-6423",
    "CVE-2020-6430",
    "CVE-2020-6431",
    "CVE-2020-6432",
    "CVE-2020-6433",
    "CVE-2020-6434",
    "CVE-2020-6435",
    "CVE-2020-6436",
    "CVE-2020-6437",
    "CVE-2020-6438",
    "CVE-2020-6439",
    "CVE-2020-6440",
    "CVE-2020-6441",
    "CVE-2020-6442",
    "CVE-2020-6443",
    "CVE-2020-6444",
    "CVE-2020-6445",
    "CVE-2020-6446",
    "CVE-2020-6447",
    "CVE-2020-6448",
    "CVE-2020-6454",
    "CVE-2020-6455",
    "CVE-2020-6456",
    "CVE-2020-6572"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/10");

  script_name(english:"Google Chrome < 81.0.4044.92 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 81.0.4044.92. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2020_04_stable-channel-update-for-desktop_7 advisory. Note that Nessus has
not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2020/04/stable-channel-update-for-desktop_7.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9efdf3c7");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1019161");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1043446");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1059669");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1031479");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1040755");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/852645");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/965611");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1043965");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1048555");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1032158");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1034519");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/639173");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/714617");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/868145");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/894477");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/959571");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1013906");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1040080");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/922882");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/933171");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/933172");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/991217");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1037872");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1067891");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 81.0.4044.92 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6572");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'81.0.4044.92', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
