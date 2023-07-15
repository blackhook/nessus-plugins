#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138077);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/14");

  script_cve_id(
    "CVE-2020-3825",
    "CVE-2020-3826",
    "CVE-2020-3846",
    "CVE-2020-3862",
    "CVE-2020-3865",
    "CVE-2020-3867",
    "CVE-2020-3868"
  );

  script_name(english:"Apple iCloud 7.x < 7.17 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An iCloud software installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the iCloud application installed on the remote Windows host is 7.x prior to 7.17. 
It is, therefore, affected by multiple vulnerabilities:

  - An arbitrary code execution vulnerability exist with in the WebKit due to multiple memory 
    corruption issues. An unauthenticated, remote attacker can exploit this by processing maliciously crafted
    web content that may lead to arbitrary code execution. (CVE-2020-3825, CVE-2020-3865, CVE-2020-3868)
    
  - An arbitrary code execution vulnerability exist with in the WebKit due to out-of-bounds read 
    issues. An unauthenticated, remote attacker can exploit this by processing a maliciously crafted image 
    that may lead to arbitrary code execution. (CVE-2020-3826)   

  - An arbitrary code execution vulnerability exist with in the WebKit due to buffer overflow 
    issues. An unauthenticated, remote attacker can exploit this by processing maliciously crafted XML file
    that may lead to an unexpected application termination or arbitrary code execution. (CVE-2020-3846)

  - An arbitrary code execution vulnerability exist with in the WebKit due to denial of service 
    issues. A malicious website may be able to cause a denial of service. (CVE-2020-3862)

  - An arbitrary code execution vulnerability exist with in the WebKit due to logic issues. 
    An unauthenticated, remote attacker can exploit this by processing maliciously crafted web content that 
    may lead to universal cross site scripting(css). (CVE-2020-3867)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210948");
  script_set_attribute(attribute:"solution", value:
"Upgrade to iCloud version 7.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3868");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:icloud_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("icloud_installed.nasl");
  script_require_keys("installed_sw/iCloud");

  exit(0);
}

include('vcf.inc');

app = 'iCloud';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  {'min_version' : '7.0',  'fixed_version' : '7.17'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
