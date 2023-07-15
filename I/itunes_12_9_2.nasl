#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119767);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/31 15:18:52");

  script_cve_id(
    "CVE-2018-4437",
    "CVE-2018-4438",
    "CVE-2018-4439",
    "CVE-2018-4440",
    "CVE-2018-4441",
    "CVE-2018-4442",
    "CVE-2018-4443",
    "CVE-2018-4464"
  );
  script_xref(name:"APPLE-SA", value:"HT209345");

  script_name(english:"Apple iTunes < 12.9.2 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on remote host is affected by multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.9.2. It is, therefore, affected by multiple
vulnerabilities as referenced in the HT209345 advisory.

  - Visiting a malicious website may lead to address bar spoofing
    (CVE-2018-4440)

  - Visiting a malicious website may lead to user interface spoofing
    (CVE-2018-4439)

  - Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2018-4437, CVE-2018-4464)

  - Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2018-4441, CVE-2018-4442, CVE-2018-4443)

  - Processing maliciously crafted web content may lead to arbitrary
    code execution. (CVE-2018-4438)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-ie/HT209345");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.9.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4464");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}
include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"iTunes Version", win_local:TRUE);
constraints = [{'fixed_version':'12.9.2'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
