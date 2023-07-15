##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141561);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2011-4343", "CVE-2017-1583");

  script_name(english:"IBM WebSphere Application Server 8.0.0.x < 8.0.0.15 / 8.5.x < 8.5.5.13 Multiple Vulnerabilities (296865)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is version 8.0.0.x prior to 8.0.0.15 or 8.5.0.x prior
to 8.5.5.13. It is, therefore, affected by two information disclosure vulnerabilities in the Java Server Faces (JSF)
subcomponent.

  - IBM WebSphere Application Server allows a remote attacker to obtain sensitive information caused by
    improper error handling by MyFaces in JSF. (CVE-2017-1583)

  - The Apache MyFaces subcomponent allows a remote attacker to obtain sensitive information. An attacker can
    exploit this vulnerability using specially crafted parameters to inject EL expressions into input fields
    mapped as view parameters and obtain sensitive information. (CVE-2011-4343)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/296865");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 8.0.0.15, 8.5.5.13, or later. Alternatively, upgrade to the minimal fix
pack levels required by the interim fix and then apply Interim Fix PI87300 and PI87299.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1583");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

app = 'IBM WebSphere Application Server';
fix = 'Interim Fix PI87300 and PI87299';

app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if ('PI87300' >< app_info['Fixes'] && 'PI87299' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.14', 'fixed_version':'8.0.0.15 or ' + fix},
  {'min_version':'8.5.0.0', 'max_version':'8.5.5.12', 'fixed_version':'8.5.5.13 or ' + fix}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
