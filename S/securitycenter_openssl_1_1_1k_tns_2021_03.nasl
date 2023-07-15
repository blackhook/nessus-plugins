##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148280);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-3449");
  script_xref(name:"IAVA", value:"2021-A-0149-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Tenable SecurityCenter 5.13.x < 5.18.0 DoS (TNS-2021-06)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is 
version 5.13.x < 5.18.0 and affected by the following OpenSSL denial of service vulnerability: 

    - An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a
    client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was
    present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL
    pointer dereference will result, leading to a crash and a denial of service attack. A server is only
    vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS
    clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of
    these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in
    OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j). (CVE-2021-3449)

Note that Nessus has not tested for this issue but has instead relied only on the
application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20210325.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-06");
  script_set_attribute(attribute:"solution", value:
"Update to Tenable SecurityCenter 5.18.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3449");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# try first local
local_version = get_kb_item('Host/SecurityCenter/Version');
if (!empty_or_null(local_version))
{
  app_info = vcf::tenable_sc::get_app_info();
}
else
{
  # otherwise, remote
  port = get_http_port(default:443, dont_exit:TRUE);
  app_info = vcf::tenable_sc::get_app_info(port:port);
}

# let's check if the version is within the vulnerable range
constraints = [
  {'min_version': '5.13.0', 'fixed_version':'5.18.0'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
