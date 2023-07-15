#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131953);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/10");

  script_cve_id(
    "CVE-2019-13725",
    "CVE-2019-13726",
    "CVE-2019-13727",
    "CVE-2019-13728",
    "CVE-2019-13729",
    "CVE-2019-13730",
    "CVE-2019-13732",
    "CVE-2019-13734",
    "CVE-2019-13735",
    "CVE-2019-13736",
    "CVE-2019-13737",
    "CVE-2019-13738",
    "CVE-2019-13739",
    "CVE-2019-13740",
    "CVE-2019-13741",
    "CVE-2019-13742",
    "CVE-2019-13743",
    "CVE-2019-13744",
    "CVE-2019-13745",
    "CVE-2019-13746",
    "CVE-2019-13747",
    "CVE-2019-13748",
    "CVE-2019-13749",
    "CVE-2019-13750",
    "CVE-2019-13751",
    "CVE-2019-13752",
    "CVE-2019-13753",
    "CVE-2019-13754",
    "CVE-2019-13755",
    "CVE-2019-13756",
    "CVE-2019-13757",
    "CVE-2019-13758",
    "CVE-2019-13759",
    "CVE-2019-13761",
    "CVE-2019-13762",
    "CVE-2019-13763",
    "CVE-2019-13764"
  );

  script_name(english:"Google Chrome < 79.0.3945.79 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 79.0.3945.79. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2019_12_stable-channel-update-for-desktop advisory. Note that Nessus has
not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2019/12/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e80c206");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1025067");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1027152");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/944619");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1024758");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1025489");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1028862");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1023817");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1025466");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1025468");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1028863");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1020899");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1013882");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1017441");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/824715");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1005596");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1011950");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1017564");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/754304");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/853670");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/990867");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/999932");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1018528");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/993706");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1010765");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1025464");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1025465");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1025470");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1025471");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/442579");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/696208");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/708595");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/884693");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/979441");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/901789");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1002687");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1004212");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1011600");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1032080");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 79.0.3945.79 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13725");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'79.0.3945.79', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
