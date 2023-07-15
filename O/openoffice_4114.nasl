#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173707);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/03");

  script_cve_id("CVE-2022-38745", "CVE-2022-40674", "CVE-2022-47502");
  script_xref(name:"IAVA", value:"2023-A-0160");

  script_name(english:"Apache OpenOffice < 4.1.14 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache OpenOffice installed on the remote host is a version prior to 4.1.14. It is, therefore, affected 
by multiple vulnerabilities:

  - libexpat before 2.4.9 has a use-after-free in the doContent function in xmlparse.c. (CVE-2022-40674)

  - Apache OpenOffice versions before 4.1.14 may be configured to add an empty entry to the Java class path. 
    This may lead to run arbitrary Java code from the current directory. (CVE-2022-38745)

  - Apache OpenOffice documents can contain links that call internal macros with arbitrary arguments. Several URI 
    Schemes are defined for this purpose. Links can be activated by clicks, or by automatic document events. The 
    execution of such links must be subject to user approval. In the affected versions of OpenOffice, approval for 
    certain links is not requested; when activated, such links could therefore result in arbitrary script execution. 
    (CVE-2022-47052)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  # https://www.openoffice.org/security/cves/CVE-2022-38745.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8e60620");
  # https://www.openoffice.org/security/cves/CVE-2022-47502.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8552ad5");
  # https://www.openoffice.org/security/cves/CVE-2022-40674.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18ed09c1");
  # https://cwiki.apache.org/confluence/display/OOOUSERS/AOO+4.1.14+Release+Notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86f9bcc9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache OpenOffice version 4.1.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40674");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("installed_sw/OpenOffice");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::openoffice::get_app_info();

# https://cwiki.apache.org/confluence/display/OOOUSERS/AOO+4.1.14+Release+Notes
var constraints = [{'fixed_version': '9811', 'fixed_display': '4.1.14 (Build 9811)'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);