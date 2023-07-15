#%NASL_MIN_LEVEL 80900
##
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/03/02. Deprecated by macosx_google_chrome_109_0_5414_87.nasl /google_chrome_109_0_5414_74.nasl.
##

include('compat.inc');

if (description)
{
  script_id(169760);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/03");

  script_cve_id(
    "CVE-2023-0128",
    "CVE-2023-0129",
    "CVE-2023-0130",
    "CVE-2023-0131",
    "CVE-2023-0132",
    "CVE-2023-0133",
    "CVE-2023-0134",
    "CVE-2023-0135",
    "CVE-2023-0136",
    "CVE-2023-0137",
    "CVE-2023-0138",
    "CVE-2023-0139",
    "CVE-2023-0140",
    "CVE-2023-0141"
  );
  script_xref(name:"IAVA", value:"2023-A-0029-S");

  script_name(english:"Google Chrome < 109.0.5414.74 Multiple Vulnerabilities (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. Please use one of the following plugins instead;
  
- For MacOS: macosx_google_chrome_109_0_5414_87.nasl (plugin ID 169761)
- For Windows: google_chrome_109_0_5414_74.nasl (plugin ID 169758)");
  # https://chromereleases.googleblog.com/2023/01/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc413e40");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1353208");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1382033");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1370028");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1357366");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1371215");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1375132");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1385709");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1385831");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1356987");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1399904");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1346675");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1367632");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1326788");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1362331");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0135");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-0138");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Please use one of the following pligins instead;\n' +
        '- MacOS: macosx_google_chrome_109_0_5414_87.nasl (plugin ID 169761)\n' +
        '- Windows: google_chrome_109_0_5414_74.nasl, (plugin ID 169758)');
