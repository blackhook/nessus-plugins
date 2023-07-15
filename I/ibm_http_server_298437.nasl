#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144074);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-9798", "CVE-2017-12618");
  script_bugtraq_id(100872, 101558);

  script_name(english:"IBM HTTP Server 7.0.0.0 < 7.0.0.45 / 8.0.0.0 < 8.0.0.15 / 8.5.0.0 < 8.5.5.13 / 9.0.0.0 < 9.0.0.6 Multiple Vulnerabilities (298437)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by multiple vulnerabilities related to Apache, as
follows:

  - Apache httpd allows remote attackers to read secret data from process memory if the Limit directive can be
    set in a user's .htaccess file, or if httpd.conf has certain misconfigurations, aka Optionsbleed. This
    affects the Apache HTTP Server through 2.2.34 and 2.4.x through 2.4.27. The attacker sends an
    unauthenticated OPTIONS HTTP request when attempting to read secret data. This is a use-after-free issue
    and thus secret data is not always sent, and the specific data depends on many factors including
    configuration. Exploitation with .htaccess can be blocked with a patch to the ap_limit_section function in
    server/core.c. (CVE-2017-9798)

  - Apache Portable Runtime Utility (APR-util) 1.6.0 and prior fail to validate the integrity of SDBM database
    files used by apr_sdbm*() functions, resulting in a possible out of bound read access. A local user with
    write access to the database can make a program or process using these functions crash, and cause a denial
    of service. (CVE-2017-12618)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/298437");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 7.0.0.45, 8.0.0.15, 8.5.5.13, 9.0.0.6, or later. Alternatively, upgrade to the
minimal fix pack levels required by the interim fix and then apply Interim Fix PI87445.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9798");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/21");
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
fix = 'Interim Fix PI87445';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PI87445' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
 { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.43', 'fixed_display' : '7.0.0.45 or ' + fix },
 { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.14', 'fixed_display' : '8.0.0.15 or ' + fix },
 { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.12', 'fixed_display' : '8.5.5.13 or ' + fix },
 { 'min_version' : '9.0.0.0', 'max_version' : '9.0.0.5', 'fixed_display' : '9.0.0.6 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
