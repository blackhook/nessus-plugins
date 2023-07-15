#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127895);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/27");

  script_cve_id(
    "CVE-2019-7957",
    "CVE-2019-7958",
    "CVE-2019-7959",
    "CVE-2019-8063",
    "CVE-2019-8236"
  );

  script_name(english:"Adobe Creative Cloud Desktop <= 4.6.1.393 Multiple Vulnerabilities (APSB19-39) (macOS)");
  script_summary(english:"Checks the version of Creative Cloud.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud installed on the remote Mac OS X
host is equal or prior to 4.6.1.393. It is, therefore, affected by
multiple vulnerabilities. The most critical of which allows an attacker
to perform arbitrary code execution in the context of the current user.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb19-39.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3603d3c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud version 4.9.0.504 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7959");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_creative_cloud_installed.nbin");
  script_require_keys("installed_sw/Creative Cloud");

  exit(0);
}

include('vcf.inc');

app = 'Creative Cloud';

app_info = vcf::get_app_info(app:app);

constraints = [
  { 'max_version' : '4.6.1.393', 'fixed_version' : '4.9.0.504' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
