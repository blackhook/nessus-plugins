##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142060);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2016-0306");

  script_name(english:"IBM WebSphere Application Server 7.0.0.x < 7.0.0.41 / 8.0.0.x < 8.0.0.13 / 8.5.x < 8.5.5.10 MiTM (CVE-2016-0306)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a man in the middle vulnerability");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is version 7.0.0.x prior to 7.0.0.41, 8.0.0.x prior to
8.0.0.13, 8.5.0.x prior to 8.5.5.10. It is, therefore, affected by a vulnerability due to weaker than expected security
caused by the improper TLS configuration if FIPS 140-2 is enabled. A remote, unauthenticated attacker can exploit this
to obtain sensitive information by using man in the middle techniques.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/545303");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 7.0.0.41, 8.0.0.13, 8.5.5.10, or later. Alternatively, upgrade to
the minimal fix pack levels required by the interim fix and then apply Interim Fix PI56190.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0306");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# Only vulnerable when FIPS 140-2 is enabled
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'IBM WebSphere Application Server';
fix = 'Interim Fix PI56190';

app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PI56190' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  {'min_version':'7.0.0.0', 'max_version':'7.0.0.39', 'fixed_display':'7.0.0.41 or ' + fix},
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.12', 'fixed_display':'8.0.0.13 or ' + fix},
  {'min_version':'8.5.0.0', 'max_version':'8.5.5.9', 'fixed_display':'8.5.5.10 or ' + fix}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
