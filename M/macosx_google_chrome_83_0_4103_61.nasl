#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136742);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-6465",
    "CVE-2020-6466",
    "CVE-2020-6467",
    "CVE-2020-6468",
    "CVE-2020-6469",
    "CVE-2020-6470",
    "CVE-2020-6471",
    "CVE-2020-6472",
    "CVE-2020-6473",
    "CVE-2020-6474",
    "CVE-2020-6475",
    "CVE-2020-6476",
    "CVE-2020-6477",
    "CVE-2020-6478",
    "CVE-2020-6479",
    "CVE-2020-6480",
    "CVE-2020-6481",
    "CVE-2020-6482",
    "CVE-2020-6483",
    "CVE-2020-6484",
    "CVE-2020-6485",
    "CVE-2020-6486",
    "CVE-2020-6487",
    "CVE-2020-6488",
    "CVE-2020-6489",
    "CVE-2020-6490",
    "CVE-2020-6491"
  );
  script_xref(name:"IAVA", value:"2020-A-0220-S");

  script_name(english:"Google Chrome < 83.0.4103.61 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 83.0.4103.61. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2020_05_stable-channel-update-for-desktop_19 advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2020/05/stable-channel-update-for-desktop_19.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26bb137e");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1073015");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1074706");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1068084");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1076708");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1067382");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1065761");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1059577");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1064519");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1049510");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1059533");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1020026");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1035315");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/946156");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1037730");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1041749");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1054966");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1068531");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/795595");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/966507");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1045787");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1047285");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1055524");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/539938");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1044277");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1050756");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1035887");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1050011");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1084009");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 83.0.4103.61 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6474");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6471");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

google_chrome_check_version(fix:'83.0.4103.61', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
