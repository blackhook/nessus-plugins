##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141915);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2018-8039");

  script_name(english:"IBM WebSphere Application Server 9.0.x < 9.0.0.9 MITM (CVE-2018-8039)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is version 9.0.x prior to 9.0.0.9. It is, therefore,
affected by a man-in-the-middle (MITM) vulnerability in the Apache CXF sub-component due to the TLS hostname
verification not working correctly with the com.sun.net.ssl interface. A remote, unauthenticated attacker can exploit
this to launch a man-in-the-middle attack.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/720065");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 9.0.0.9 or later. Alternatively, upgrade to the minimal fix pack levels
required by the interim fix and then apply Interim Fix PH01221.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8039");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/27");

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

# Only affects JAX-RS, which we don't check for
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'IBM WebSphere Application Server';
fix = 'Interim Fix PH01221';

app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if ('PH01221' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  {'min_version':'9.0.0.0', 'max_version':'9.0.0.8', 'fixed_version':'9.0.0.9 or ' + fix}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
