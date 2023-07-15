#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164651);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2022-33935");
  script_xref(name:"IAVB", value:"2022-B-0030");

  script_name(english:"EMC Data Protection Advisor < 19.7 Build B4 XSS (DSA-2022-107)");

  script_set_attribute(attribute:"synopsis", value:
"The remote application may be affected by a stored cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the application is below version 19.7 Build B4. It is, therefore, affected by a
stored cross-site scripting vulnerability. When a victim user accesses the data store through their browsers, the
malicious code gets executed by the web browser in the context of the vulnerable web application. Exploitation may lead
to information disclosure, session theft, or client-side request forgery.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number");
  # https://support.emc.com/downloads/829_Data-Protection-Advisor
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf340180");
  # https://www.dell.com/support/kbdoc/en-us/000201824/dsa-2022-107-dell-emc-data-protection-advisor-dpa-security-update-for-stored-cross-site-scripting-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc70cb23");
  script_set_attribute(attribute:"solution", value:
"Upgrade EMC Data Protection Advisor to version 19.7 Build B4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33935");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:data_protection_advisor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("win_emc_dpa_installed.nbin");
  script_require_keys("installed_sw/EMC Data Protection Advisor");

  exit(0);
}


include('vcf.inc');

var app_name = 'EMC Data Protection Advisor';
var app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'fixed_version' : '19.7', 'fixed_display' : '19.7 Build B4' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
