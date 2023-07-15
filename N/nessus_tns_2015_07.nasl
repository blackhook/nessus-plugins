#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86949);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2015-1788", "CVE-2015-1789");
  script_bugtraq_id(75156, 75158);

  script_name(english:"Nessus 5.x < 5.2.12 / 6.x < 6.4 Multiple OpenSSL Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Nessus installation is affected by multiple denial of
service vulnerabilities in the bundled OpenSSL component.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable Nessus running
on the remote host is version 5.x prior to 5.2.12 or 6.x prior to 6.4.
It is, therefore, affected by multiple denial of service
vulnerabilities in the bundled OpenSSL component :

  - A denial of service vulnerability exists when processing
    an ECParameters structure due to an infinite loop that
    occurs when a specified curve is over a malformed binary
    polynomial field. A remote attacker can exploit this to
    perform a denial of service against any system that
    processes public keys, certificate requests, or
    certificates. This includes TLS clients and TLS servers
    with client authentication enabled. (CVE-2015-1788)

  - A denial of service vulnerability exists due to improper
    validation of the content and length of the ASN1_TIME
    string by the X509_cmp_time() function. A remote
    attacker can exploit this, via a malformed certificate
    and CRLs of various sizes, to cause a segmentation
    fault, resulting in a denial of service condition. TLS
    clients that verify CRLs are affected. TLS clients and
    servers with client authentication enabled may be
    affected if they use custom verification callbacks.
    (CVE-2015-1789)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-07");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150611.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus 5.2.12 / 6.4 or later.");
    script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1789");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");      				  
  script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include('vcf_extras.inc');

var app_info, constraints;

app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "5.0.0",  "fixed_version" : "5.2.12" },
  { "min_version" : "6.0.0",  "fixed_version" : "6.4.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING); 
