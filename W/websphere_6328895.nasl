##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141469);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2020-4578");

  script_name(english:"IBM WebSphere Application Server 7.0.0.x <= 7.0.0.45 / 8.0.0.x <= 8.0.0.15 / 8.5.x < 8.5.5.18 / 9.0.x < 9.0.5.6 XSS (CVE-2020-4578)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a cross-site scripting vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of WebSphere Application Server installed on the remote host is 7.0.0.x <= 7.0.0.45, 8.0.0.x <= 8.0.0.15,
8.5.x < 8.5.5.18, or 9.0.x < 9.0.5.6. It is, therefore,  vulnerable to cross-site scripting. This vulnerability allows
users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to
credentials disclosure within a trusted session.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6328895");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 8.5.5.18, 9.0.5.6 or later. Alternatively, upgrade to the minimal fix pack
levels required by the interim fix and then apply Interim Fix PH26220.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4578");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/15");

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
fix = 'Interim Fix PH26220';

get_install_count(app_name:app, exit_if_zero:TRUE);
app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if ('PH26220' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  {'min_version':'7.0.0.0', 'max_version':'7.0.0.45', 'fixed_version':fix},
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.15', 'fixed_version':fix},
  {'min_version':'8.5.0.0', 'max_version':'8.5.5.17', 'fixed_version':'8.5.5.18 or ' + fix},
  {'min_version':'9.0.0.0', 'max_version':'9.0.5.5', 'fixed_version':'9.0.5.6 or ' + fix}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{'xss':TRUE}
);
