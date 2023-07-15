##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142141);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2015-0254");

  script_name(english:"IBM WebSphere Application Server 6.1.0.x <= 6.1.0.47 / 7.0.0.x < 7.0.0.43 / 8.0.0.x < 8.0.0.13 / 8.5.x < 8.5.5.10 XXE (CVE-2015-0254)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by an XML external entity injection vulnerability");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is version 6.1.x through 6.1.0.47, 7.0.0.x prior to
7.0.0.43, 8.0.0.x prior to 8.0.0.13, or 8.5.0.x prior to 8.5.5.10. It is, therefore, affected by an XML external entity
injection vulnerability in the Apache Standard Taglibs subcomponent due to an incorrectly configured XML parser
accepting XML external entities from an untrusted source. An unauthenticated, remote attacker can exploit this, via
specially crafted XML data, to execute arbitrary code on the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/544293");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 7.0.0.43, 8.0.0.13, 8.5.5.10, or later. Alternatively, upgrade to the
minimal fix pack levels required by the interim fix and then apply Interim Fix PI56811.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/30");

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
fix = 'Interim Fix PI56811';

app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if ('PI56811' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  {'min_version':'6.1.0.0', 'max_version':'6.1.0.47', 'fixed_display':fix},
  {'min_version':'7.0.0.0', 'max_version':'7.0.0.41', 'fixed_display':'7.0.0.43 or ' + fix},
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.12', 'fixed_display':'8.0.0.13 or ' + fix},
  {'min_version':'8.5.0.0', 'max_version':'8.5.5.9', 'fixed_display':'8.5.5.10 or ' + fix}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
