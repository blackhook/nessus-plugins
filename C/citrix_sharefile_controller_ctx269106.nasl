#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137000);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/04");

  script_cve_id("CVE-2020-7473", "CVE-2020-8982", "CVE-2020-8983");

  script_name(english:"ShareFile Documents Unauthenticated Access (CTX269106)");

  script_set_attribute(attribute:"synopsis", value:
"The Citrix Sharefile Storage Zones Controller instance found
on the remote host is affected by an unauthenticated access vulnerability..");
  script_set_attribute(attribute:"description", value:
"Security issues have been identified in customer-managed Citrix ShareFile storage zone 
controllers. These vulnerabilities, if exploited, would allow an unauthenticated attacker 
to compromise the storage zones controller potentially giving an attacker the ability 
to access ShareFile users’ documents and folders.

Storage zones created using a vulnerable version of the storage zones controller are 
at risk even if the storage zones controller has been subsequently updated.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX269106");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7473");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:sharefile");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_sharefile_controller_win_installed.nbin", "citrix_sharefile_controller_web_detect.nbin");
  script_require_keys("installed_sw/Citrix ShareFile StorageZones Controller");

  exit(0);
}

include('vcf.inc');

app = 'Citrix ShareFile StorageZones Controller';

app_info = vcf::get_app_info(app:app);

constraints = [
  { "min_version" : "5.9.0",  "fixed_version" : "5.9.1" },
  { "min_version" : "5.8.0",  "fixed_version" : "5.8.1" },
  { "min_version" : "5.7.0",  "fixed_version" : "5.7.1" },
  { "min_version" : "5.6.0",  "fixed_version" : "5.6.1" },
  { "min_version" : "5.5.0",  "fixed_version" : "5.5.1" },
  { "min_version" : "1", "max_version": "5.4.99999", "fixed_version" : "5.10.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
