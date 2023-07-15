#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159504);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id("CVE-2021-44141", "CVE-2021-44142", "CVE-2022-0336");

  script_name(english:"QNAP QTS / QuTS hero Multiple Vulnerabilities in Samba (QSA-22-03)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS or QuTS hero on the remote host is affected by multiple vulnerabilities in the Samba component,
as follows:

  - The Samba vfs_fruit module uses extended file attributes (EA, xattr) to provide '...enhanced compatibility
    with Apple SMB clients and interoperability with a Netatalk 3 AFP fileserver.' Samba versions prior to
    4.13.17, 4.14.12 and 4.15.5 with vfs_fruit configured allow out-of-bounds heap read and write via
    specially crafted extended file attributes. A remote attacker with write access to extended file
    attributes can execute arbitrary code with the privileges of smbd, typically root. (CVE-2021-44142)

  - All versions of Samba prior to 4.15.5 are vulnerable to a malicious client using a server symlink to
    determine if a file or directory exists in an area of the server file system not exported under the share
    definition. SMB1 with unix extensions has to be enabled in order for this attack to succeed.
    (CVE-2021-44141)

  - Samba AD users able to write to an account can impersonate existing services, intercept traffic, and cause
    a denial of service (DoS). (CVE-2022-0336)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/qsa-22-03");
  script_set_attribute(attribute:"solution", value:
"Apply the workaround and upgrade to the relevant fixed version referenced in the QSA-22-03 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44142");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0336");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:quts_hero");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin");
  script_require_ports("installed_sw/QNAP QTS", "installed_sw/QNAP QuTS hero");

  exit(0);
}

include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
{'product':'QTS', 'min_version':'4.3', 'max_version':'4.3.3', 'Number':'1945', 'Build':'20220303', 'fixed_display':'QTS 4.3.3.1945 build 20220303'},
{'product':'QTS', 'min_version':'4.3.4', 'max_version':'4.3.4', 'Number':'1976', 'Build':'20220303', 'fixed_display':'QTS 4.3.4.1976 build 20220303'},
{'product':'QTS', 'min_version':'4.3.6', 'max_version':'4.3.6', 'Number':'1965', 'Build':'20220302', 'fixed_display':'QTS 4.3.6.1965 build 20220302 '},
{'product':'QTS', 'min_version':'4.5.4', 'max_version':'4.5.4', 'Number':'1931', 'Build':'20220128', 'fixed_display':'QTS 4.5.4.1931 build 20220128'},
{'product':'QTS', 'min_version':'5.0', 'max_version':'5.0.0', 'Number':'1932', 'Build':'20220129', 'fixed_display':'QTS 5.0.0.1932 build 20220129'},
{'product':'QuTS hero', 'min_version':'0.0', 'max_version':'4.5.4', 'Number':'1951', 'Build':'20220218', 'fixed_display':'QuTS hero h4.5.4.1951 build 20220218'},
{'product':'QuTS hero', 'min_version':'5.0', 'max_version':'5.0.0', 'Number':'1949', 'Build':'20220215', 'fixed_display':'QuTS hero h5.0.0.1949 build 20220215'}
];

vcf::qnap::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
