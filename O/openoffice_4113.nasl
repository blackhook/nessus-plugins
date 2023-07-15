#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164180);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-37400", "CVE-2022-37401");
  script_xref(name:"IAVA", value:"2022-A-0331-S");

  script_name(english:"Apache OpenOffice < 4.1.13 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache OpenOffice installed on the remote host is a version prior to 4.1.13. It is, therefore, affected 
by multiple vulnerabilities:

  - Apache OpenOffice supports the storage of passwords for web connections in the user's 
    configuration database. The stored passwords are encrypted with a single master key 
    provided by the user. A flaw in OpenOffice existed where the required initialization 
    vector for encryption was always the same which weakens the security of the encryption 
    making them vulnerable if an attacker has access to the user's configuration data. 
    (CVE-2022-37400)

  - A flaw in OpenOffice existed where master key was poorly encoded resulting in weakening 
    its entropy from 128 to 43 bits making the stored passwords vulnerable to a brute force 
    attack if an attacker has access to the users stored config. (CVE-2022-37401)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  # https://www.openoffice.org/security/cves/CVE-2022-37400.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5c15448");
  # https://www.openoffice.org/security/cves/CVE-2022-37401.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b62874d1");
  # https://cwiki.apache.org/confluence/display/OOOUSERS/AOO+4.1.13+Release+Notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3b3105a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache OpenOffice version 4.1.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37400");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-37401");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("installed_sw/OpenOffice");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::openoffice::get_app_info();

var constraints = [{'fixed_version': '9810', 'fixed_display': '4.1.13 (Build 9810)'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
