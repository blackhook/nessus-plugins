##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141914);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2015-4000");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"IBM WebSphere Application Server 6.1.0.x <= 6.1.0.47 / 7.0.0.x < 7.0.0.39 / 8.0.0.x < 8.0.0.11 / 8.5.x < 8.5.5.7 LogJam (CVE-2015-4000)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is version 6.1.0.x through 6.1.0.47, 7.0.0.x prior to
7.0.0.39, 8.0.0.x prior to 8.0.0.11, or 8.5.0.x prior to 8.5.5.7. It is, therefore, affected by an information
disclosure vulnerability due to a failure to properly convey a DHE_EXPORT ciphersuite choice (LogJam). A remote,
unauthenticated attacker can exploit this, using man in the middle techniques, to force a downgrade to 512-bit export-
grade cipher in order to recover the session key and modify the contents of the traffic.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/527817");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 7.0.0.30, 8.0.0.11, 8.5.5.7, or later. Alternatively, upgrade to the
minimal fix pack levels required by the interim fix and then apply Interim Fix and update recommended in the vendor
advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4000");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# Not checking workarounds
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'IBM WebSphere Application Server';
fix = 'Interim Fix ';

get_install_count(app_name:app, exit_if_zero:TRUE);
app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if (app_info['version'] =~ "^8\.5")
{
  pi = 'PI42776';
  fix += pi;
}
else if (app_info['version'] =~ "^8\.0")
{
  pi = 'PI42777';
  fix += pi;
}
else if (app_info['version'] =~ "^7\.0")
{
  pi = 'PI42778';
  fix += pi;
}
else if (app_info['version'] =~ "^6\.1")
{
  pi = 'PI42779';
  fix += pi;
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app, app_info['version']);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if (pi >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  {'min_version':'6.1.0.0', 'max_version':'6.1.0.47', 'fixed_version':fix},
  {'min_version':'7.0.0.0', 'max_version':'7.0.0.37', 'fixed_version':'7.0.0.39 or ' + fix},
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.10', 'fixed_version':'8.0.0.11 or ' + fix},
  {'min_version':'8.5.0.0', 'max_version':'8.5.5.6', 'fixed_version':'8.5.5.7 or ' + fix}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
