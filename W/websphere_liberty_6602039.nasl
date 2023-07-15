#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164809);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/07");

  script_cve_id("CVE-2019-11777");

  script_name(english:"IBM WebSphere Application Server Liberty 17.0.0.3 < 22.0.0.8 (6602039)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Application Server Liberty running on the remote host is affected by a vulnerability as
referenced in the 6602039 advisory.

  - In the Eclipse Paho Java client library version 1.2.0, when connecting to an MQTT server using TLS and
    setting a host name verifier, the result of that verification is not checked. This could allow one MQTT
    server to impersonate another and provide the client library with incorrect information. (CVE-2019-11777)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6602039");
  script_set_attribute(attribute:"solution", value:
"Update to IBM WebSphere Application Server Liberty version 22.0.0.8 or later. Alternatively, upgrade to the minimal fix
pack levels required by the interim fix and then apply Interim Fix PH45750.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11777");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_liberty_detect.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

var app = 'IBM WebSphere Application Server';
var app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if (app_info['Product'] != app + ' Liberty')
  audit(AUDIT_HOST_NOT, app + ' Liberty');

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if ('PH45750' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

var constraints = [
  { 'min_version' : '17.0.0.3', 'fixed_version' : '22.0.0.8', 'fixed_display' : '22.0.0.8 or Interim Fix PH45750' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
