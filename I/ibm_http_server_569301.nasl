#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144773);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-0702",
    "CVE-2016-7056",
    "CVE-2017-3732",
    "CVE-2017-3736",
    "CVE-2018-1426",
    "CVE-2018-1427",
    "CVE-2018-1447"
  );
  script_bugtraq_id(
    83740,
    95375,
    95814,
    101666,
    103536,
    104511,
    105580
  );

  script_name(english:"IBM HTTP Server 7.0.0.0 <= 7.0.0.43 / 8.0.0.0 <= 8.0.0.14 / 8.5.0.0 < 8.5.5.14 / 9.0.0.0 < 9.0.0.8 Multiple Vulnerabilities (569301)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by multiple vulnerabilities, including the following:

  - IBM GSKit (IBM DB2 for Linux, UNIX and Windows 9.7, 10.1, 10.5, and 11.1) duplicates the PRNG state across
    fork() system calls when multiple ICC instances are loaded which could result in duplicate Session IDs and
    a risk of duplicate key material. (CVE-2018-1426)

  - The GSKit (IBM Spectrum Protect 7.1 and 7.2) and (IBM Spectrum Protect Snapshot 4.1.3, 4.1.4, and 4.1.6)
    CMS KDB logic fails to salt the hash function resulting in weaker than expected protection of passwords. A
    weak password may be recovered. Note: After update the customer should change password to ensure the new
    password is stored more securely. Products should encourage customers to take this step as a high priority
    action. (CVE-2018-1447)

  - There is a carry propagating bug in the x86_64 Montgomery squaring procedure in OpenSSL 1.0.2 before
    1.0.2k and 1.1.0 before 1.1.0d. No EC algorithms are affected. Analysis suggests that attacks against RSA
    and DSA as a result of this defect would be very difficult to perform and are not believed likely. Attacks
    against DH are considered just feasible (although very difficult) because most of the work necessary to
    deduce information about a private key may be performed offline. The amount of resources required for such
    an attack would be very significant and likely only accessible to a limited number of attackers. An
    attacker would additionally need online access to an unpatched system using the target private key in a
    scenario with persistent DH parameters and a private key that is shared between multiple clients. For
    example this can occur by default in OpenSSL DHE based SSL/TLS ciphersuites. Note: This issue is very
    similar to CVE-2015-3193 but must be treated as a separate problem. (CVE-2017-3732)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/569301");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 7.0.0.45, 8.5.5.14, 9.0.0.8, or later. Alternatively, upgrade to the minimal fix
pack levels required by the interim fix and then apply Interim Fix PI91913 or PI94222.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1426");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/06");

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
fix = 'Interim Fix PI94222';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PI91913' >< app_info['Fixes'] || 'PI94222' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
 { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.43', 'fixed_display' : '7.0.0.45 or Interim Fix PI91913'},
 { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.14', 'fixed_display' : fix },
 { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.13', 'fixed_display' : '8.5.5.14 or ' + fix },
 { 'min_version' : '9.0.0.0', 'max_version' : '9.0.0.7', 'fixed_display' : '9.0.0.8 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
