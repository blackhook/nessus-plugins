#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144073);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-17199");
  script_bugtraq_id(106742);

  script_name(english:"IBM HTTP Server 9.0.0.0 < 9.0.0.11 Security Bypass (869064)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by a vulnerability related to Apache HTTP Server.
In Apache HTTP Server 2.4 release 2.4.37 and prior, mod_session checks the session expiry time before decoding the
session. This causes session expiry time to be ignored for mod_session_cookie sessions since the expiry time is loaded
when the session is decoded.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/869064");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 9.0.0.11 or later. Alternatively, upgrade to the minimal fix pack levels required by
the interim fix and then apply Interim Fix PH06010.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17199");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_http_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM HTTP Server (IHS)");

  exit(0);
}


include('vcf.inc');

app = 'IBM HTTP Server (IHS)';
fix = 'Interim Fix PH06010';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PH06010' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
 { 'min_version' : '9.0.0.0', 'max_version' : '9.0.0.10', 'fixed_display' : '9.0.0.11 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
