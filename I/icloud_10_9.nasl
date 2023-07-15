#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138078);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/02");

  script_cve_id(
    "CVE-2019-8834",
    "CVE-2019-8835",
    "CVE-2019-8844",
    "CVE-2019-8846",
    "CVE-2019-8848",
    "CVE-2019-15903"
  );

  script_name(english:"Apple iCloud 10.x < 10.9 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An iCloud software installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the iCloud application installed on the remote Windows host is 10.x prior to 10.9. 
It is, therefore, affected by multiple vulnerabilities:
    
  - An arbitrary code execution vulnerability exist with in the WebKit due to configuration issue issues. 
    An attacker in privileged network position may be able to bypass HSTS for a limited number of specific 
    top-level domains previously not in the HSTS preload list. (CVE-2019-8834)   

  - An arbitrary code execution vulnerability exist with in the WebKit due to maliciously crafted
    content issues. An unauthenticated, remote attacker can exploit this by processing maliciously
    crafted web content may lead to arbitrary code execution. (CVE-2019-8835,CVE-2019-8844, CVE-2019-8846)

  - An application may be able to gain elevated privileges (CVE-2019-8848)

  - A vulnerability exists with in the WebKit due to improper parsing of XML data. An unauthenticated, 
    remote attacker can exploit this by parsing a maliciously crafted XML file may lead to disclosure of 
    user information. (CVE-2019-15903)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210794");
  script_set_attribute(attribute:"solution", value:
"Upgrade to iCloud version 10.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8846");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/05");
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
  {'min_version' : '10.0',  'fixed_version' : '10.9'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);