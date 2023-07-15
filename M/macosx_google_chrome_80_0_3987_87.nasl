#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133464);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id(
    "CVE-2019-18197",
    "CVE-2019-19923",
    "CVE-2019-19926",
    "CVE-2020-6381",
    "CVE-2020-6382",
    "CVE-2020-6385",
    "CVE-2020-6387",
    "CVE-2020-6388",
    "CVE-2020-6389",
    "CVE-2020-6390",
    "CVE-2020-6391",
    "CVE-2020-6392",
    "CVE-2020-6393",
    "CVE-2020-6394",
    "CVE-2020-6395",
    "CVE-2020-6396",
    "CVE-2020-6397",
    "CVE-2020-6398",
    "CVE-2020-6399",
    "CVE-2020-6400",
    "CVE-2020-6401",
    "CVE-2020-6402",
    "CVE-2020-6403",
    "CVE-2020-6404",
    "CVE-2020-6405",
    "CVE-2020-6406",
    "CVE-2020-6408",
    "CVE-2020-6409",
    "CVE-2020-6410",
    "CVE-2020-6411",
    "CVE-2020-6412",
    "CVE-2020-6413",
    "CVE-2020-6414",
    "CVE-2020-6415",
    "CVE-2020-6416",
    "CVE-2020-6417"
  );

  script_name(english:"Google Chrome < 80.0.3987.87 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 80.0.3987.87. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2020_02_stable-channel-update-for-desktop advisory. Note that Nessus has
not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2020/02/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc6a32b5");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1034394");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1031909");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1020745");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1042700");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1035399");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1042535");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1042879");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1042933");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1045874");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1017871");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1030411");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1035058");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1014371");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1022855");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1035271");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1027408");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1032090");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1039869");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1038036");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1017707");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1029375");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1006012");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1024256");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1042145");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1042254");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1042578");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1026546");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1037889");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/881675");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/929711");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/968505");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1005713");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1021855");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1029576");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1031895");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1033824");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1048330");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 80.0.3987.87 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6416");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'80.0.3987.87', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
