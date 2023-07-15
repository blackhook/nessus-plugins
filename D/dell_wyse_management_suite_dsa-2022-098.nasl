##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161952);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/18");

  script_cve_id("CVE-2022-0778", "CVE-2022-22965");
  script_xref(name:"IAVA", value:"2022-A-0121-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/25");

  script_name(english:"Dell Wyse Management Suite < 3.6.1 Multiple Vulnerabilities (DSA-2022-098)");

  script_set_attribute(attribute:"synopsis", value:
"Dell Wyse Management Suite installed on the local host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell Wyse Management Suite installed on the remote host is prior to tested version. It is, therefore,
affected by multiple vulnerabilities as referenced in the DSA-2022-098 advisory.

  - The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop
    forever for non-prime moduli. Internally this function is used when parsing certificates that contain
    elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point
    encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has
    invalid explicit curve parameters. Since certificate parsing happens prior to verification of the
    certificate signature, any process that parses an externally supplied certificate may thus be subject to a
    denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they
    can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients
    consuming server certificates - TLS servers consuming client certificates - Hosting providers taking
    certificates or private keys from customers - Certificate authorities parsing certification requests from
    subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that
    use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS
    issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate
    which makes it slightly harder to trigger the infinite loop. However any operation which requires the
    public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-
    signed certificate to trigger the loop during verification of the certificate signature. This issue
    affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the
    15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected
    1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc). (CVE-2022-0778)

  - A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution
    (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR
    deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not
    vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be
    other ways to exploit it. (CVE-2022-22965)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000198486/dsa-2022-098-dell-wyse-management-suite-security-update-for-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?beac8880");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Wyse Management Suite 3.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22965");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Spring Framework Class property RCE (Spring4Shell)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:wyse_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_wyse_management_suite_win_installed.nbin");
  script_require_keys("installed_sw/Dell Wyse Management Suite", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Dell Wyse Management Suite', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '3.6.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
