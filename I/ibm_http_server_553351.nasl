#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144079);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-2183");
  script_bugtraq_id(92630);

  script_name(english:"IBM HTTP Server 7.0.0.0 < 7.0.0.45 / 8.0.0.0 < 8.0.0.15 / 8.5.0.0 < 8.5.5.13 / 9.0.0.0 < 9.0.0.6 Sweet32:Birthday Attack (553351)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by a vulnerability. The DES and Triple DES
ciphers, as used in the TLS, SSH, and IPSec protocols and other protocols and products, have a birthday bound of
approximately four billion blocks, which makes it easier for remote attackers to obtain cleartext data via a birthday
attack against a long-duration encrypted session, as demonstrated by an HTTPS session using Triple DES in CBC mode, aka
a 'Sweet32' attack.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/553351");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 7.0.0.45, 8.0.0.15, 8.5.5.13, 9.0.0.6, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2183");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_http_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM HTTP Server (IHS)", "Settings/ParanoidReport");

  exit(0);
}


include('vcf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'IBM HTTP Server (IHS)';
app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [
 { 'min_version' : '7.0.0.0', 'fixed_version' : '7.0.0.45' },
 { 'min_version' : '8.0.0.0', 'fixed_version' : '8.0.0.15' },
 { 'min_version' : '8.5.0.0', 'fixed_version' : '8.5.5.13' },
 { 'min_version' : '9.0.0.0', 'fixed_version' : '9.0.0.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
