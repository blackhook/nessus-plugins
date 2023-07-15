#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138075);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-3885",
    "CVE-2020-3887",
    "CVE-2020-3894",
    "CVE-2020-3895",
    "CVE-2020-3897",
    "CVE-2020-3899",
    "CVE-2020-3900",
    "CVE-2020-3901",
    "CVE-2020-3902",
    "CVE-2020-3909",
    "CVE-2020-3910",
    "CVE-2020-3911",
    "CVE-2020-9783"
  );

  script_name(english:"Apple iCloud 7.x < 7.18 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An iCloud software installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the iCloud application installed on the remote Windows host is 7.x prior to 7.18. 
It is, therefore, affected by multiple vulnerabilities:

  - A logic issue was addressed with improved restrictions. A file URL may be incorrectly processed. 
    (CVE-2020-3885)

  - A logic issue was addressed with improved restrictions. A download's origin may be incorrectly 
    associated. (CVE-2020-3887)
    
  - A race condition was addressed with additional validation. An application may be able to read 
    restricted memory. (CVE-2020-3894)   

  - An arbitrary code execution vulnerability exist with in the WebKit due to maliciously crafted
    content issues. An unauthenticated, remote attacker can exploit this by processing maliciously
    crafted web content may lead to arbitrary code execution. (CVE-2020-3895, CVE-2020-3899, CVE-2020-3900)

  - An arbitrary code execution vulnerability exist with in the WebKit due to type confusion
    issues. A remote attacker may be able to cause arbitrary code execution. (CVE-2020-3897, CVE-2020-3901)

  - An arbitrary code execution vulnerability exist with in the WebKit due to input validation 
    issues. An unauthenticated, remote attacker can exploit this by processing maliciously crafted 
    web content may lead to arbitrary code execution. (CVE-2020-3902)

  - An arbitrary code execution vulnerability exist with in the WebKit due to buffer overflow 
    issues. Multiple issues in libxml2. (CVE-2020-3909, CVE-2020-3910, CVE-2020-3911)

  - An arbitrary code execution vulnerability exist with in the WebKit due to use after free 
    issues. An unauthenticated, remote attacker can exploit this by processing maliciously crafted 
    web content may lead to arbitrary code execution. (CVE-2020-9783)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211107");
  script_set_attribute(attribute:"solution", value:
"Upgrade to iCloud version 7.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3899");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-3911");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:icloud_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("icloud_installed.nasl");
  script_require_keys("installed_sw/iCloud");

  exit(0);
}

include('vcf.inc');

app = 'iCloud';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  {'min_version' : '7.0',  'fixed_version' : '7.18'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
