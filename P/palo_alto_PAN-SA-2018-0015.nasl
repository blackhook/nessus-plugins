#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(123512);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2018-0732", "CVE-2018-0737", "CVE-2018-0739");
  script_bugtraq_id(103518, 103766, 104442);

  script_name(english:"Palo Alto Networks PAN-OS 6.1.x <= 6.1.20  / 7.1.x < 7.1.21 / 8.0.x < 8.0.14 / 8.1.x < 8.1.4 Multiple Vulnerabilities (PAN-SA-2018-0015)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host
is 6.1.x including 6.1.20 or 7.1.x prior to 7.1.21 or 8.0.x prior to
8.0.14 or 8.1.x prior to 8.1.4. It is, therefore, affected by multiple
vulnerabilities :

  - A denial of service (DoS) vulnerability that exists in OpenSSL
   due to failure of handling the exception conditions during the TLS
   handshake. An authenticated, remote attacker can exploit this issue
   , via malicious server to send large prime value to the client to
   spend unreasonably long time for generating the key for this prime
   resulting hang until the client finished. (CVE-2018-0732)

  - An information disclosure vulnerability that exists in OpenSSL
   RSA key generation algorithm due to a cache timing side channel
   attack. An authenticated, local attacker can exploit this issue,
   via cache timing attacks during the RSA key generation process,
   to recover the private key. (CVE-2018-0737)

  - A denial of service (DoS) vulnerability that exists in OpenSSL due
   to a constructed ASN.1 types with a recursive definition. An
   unauthenticated, remote attacker can exploit this issue, via
   creating malicious input with excessive recursion, to cause the
   Denial Of Service attack. (CVE-2018-0739)");
  # https://securityadvisories.paloaltonetworks.com/Home/Detail/133
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc854806");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.1.21 / 8.0.14 / 8.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version", "Host/Palo_Alto/Firewall/Source");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::palo_alto::initialize();

app_name = 'Palo Alto Networks PAN-OS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Palo_Alto/Firewall/Full_Version', kb_source:'Host/Palo_Alto/Firewall/Source');

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '6.1', 'max_version' : '6.1.20', 'fixed_display' : 'PAN-OS 6.1 will not have a fix.' },
  { 'min_version' : '7.1', 'fixed_version' : '7.1.21' },
  { 'min_version' : '8.0', 'fixed_version' : '8.0.14' },
  { 'min_version' : '8.1', 'fixed_version' : '8.1.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
