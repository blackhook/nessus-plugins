#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136410);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2020-4329");
  script_xref(name:"IAVA", value:"2020-A-0192-S");

  script_name(english:"IBM WebSphere Application Server 7.0 < 7.0.0.46 / 8.0 < 8.0.0.16 / 8.5 < 8.5.5.18 / 9.0 < 9.0.5.4 / Liberty 17.0.0.3 < 20.0.0.5 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is version 7.0 prior to 7.0.0.46, 8.0 prior to 8.0.0.16, 
8.5 prior to 8.5.5.18, 9.0 prior to 9.0.5.4, or 17.0.0.3 (Liberty) prior to 20.0.0.5 could allow a remote, authenticated 
attacker to obtain sensitive information, caused by improper parameter checking.  This could be exploited to conduct 
spoofing attacks. (CVE-2020-4329).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6201862");
  script_set_attribute(attribute:"solution", value:
"Apply the Fix Pack recommended in the vendor advisory. Alternatively, upgrade to the minimal fix pack levels required
by the interim fix and then apply Interim Fix PH20847.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4329");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

app = 'IBM WebSphere Application Server';
fix = 'Interim Fix PH20847';

get_install_count(app_name:app, exit_if_zero:TRUE);
app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if ('PH20847' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  {'min_version':'7.0.0.0', 'max_version':'7.0.0.45', 'fixed_version':'7.0.0.46 or ' + fix},
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.15', 'fixed_version':'8.0.0.16 or ' + fix},
  {'min_version':'8.5.0.0', 'max_version':'8.5.5.17', 'fixed_version':'8.5.5.18 or ' + fix},
  {'min_version':'9.0.0.0', 'max_version':'9.0.5.3', 'fixed_version':'9.0.5.4 or ' + fix},
  {'min_version':'17.0.0.3', 'max_version':'20.0.0.4', 'fixed_version':'20.0.0.5 or ' + fix}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
