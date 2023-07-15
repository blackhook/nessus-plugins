#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164555);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2020-1971",
    "CVE-2020-15862",
    "CVE-2020-25684",
    "CVE-2020-25685",
    "CVE-2020-25686",
    "CVE-2021-3156"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/27");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0003");

  script_name(english:"Nutanix AHV : Multiple Vulnerabilities (NXSA-AHV-20201105.1045)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20201105.1045. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AHV-20201105.1045 advisory.

  - Net-SNMP through 5.7.3 has Improper Privilege Management because SNMP WRITE access to the EXTEND MIB
    provides the ability to run arbitrary commands as root. (CVE-2020-15862)

  - The X.509 GeneralName type is a generic type for representing different types of names. One of those name
    types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different
    instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both
    GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a
    possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1)
    Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in
    an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp
    authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an
    attacker can control both items being compared then that attacker could trigger a crash. For example if
    the attacker can trick a client or server into checking a malicious certificate against a malicious CRL
    then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a
    certificate. This checking happens prior to the signatures on the certificate and CRL being verified.
    OpenSSL's s_server, s_client and verify tools have support for the -crl_download option which implements
    automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an
    unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of
    EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will
    accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue.
    Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected
    1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w). (CVE-2020-1971)

  - A flaw was found in dnsmasq before version 2.83. When getting a reply from a forwarded query, dnsmasq
    checks in the forward.c:reply_query() if the reply destination address/port is used by the pending
    forwarded queries. However, it does not use the address/port to retrieve the exact forwarded query,
    substantially reducing the number of attempts an attacker on the network would have to perform to forge a
    reply and get it accepted by dnsmasq. This issue contrasts with RFC5452, which specifies a query's
    attributes that all must be used to match a reply. This flaw allows an attacker to perform a DNS Cache
    Poisoning attack. If chained with CVE-2020-25685 or CVE-2020-25686, the attack complexity of a successful
    attack is reduced. The highest threat from this vulnerability is to data integrity. (CVE-2020-25684)

  - A flaw was found in dnsmasq before version 2.83. When getting a reply from a forwarded query, dnsmasq
    checks in forward.c:reply_query(), which is the forwarded query that matches the reply, by only using a
    weak hash of the query name. Due to the weak hash (CRC32 when dnsmasq is compiled without DNSSEC, SHA-1
    when it is) this flaw allows an off-path attacker to find several different domains all having the same
    hash, substantially reducing the number of attempts they would have to perform to forge a reply and get it
    accepted by dnsmasq. This is in contrast with RFC5452, which specifies that the query name is one of the
    attributes of a query that must be used to match a reply. This flaw could be abused to perform a DNS Cache
    Poisoning attack. If chained with CVE-2020-25684 the attack complexity of a successful attack is reduced.
    The highest threat from this vulnerability is to data integrity. (CVE-2020-25685)

  - A flaw was found in dnsmasq before version 2.83. When receiving a query, dnsmasq does not check for an
    existing pending request for the same name and forwards a new request. By default, a maximum of 150
    pending queries can be sent to upstream servers, so there can be at most 150 queries for the same name.
    This flaw allows an off-path attacker on the network to substantially reduce the number of attempts that
    it would have to perform to forge a reply and have it accepted by dnsmasq. This issue is mentioned in the
    Birthday Attacks section of RFC5452. If chained with CVE-2020-25684, the attack complexity of a
    successful attack is reduced. The highest threat from this vulnerability is to data integrity.
    (CVE-2020-25686)

  - Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which
    allows privilege escalation to root via sudoedit -s and a command-line argument that ends with a single
    backslash character. (CVE-2021-3156)

  - A heap-based buffer overflow was found in the way sudo parses command line arguments. This flaw is
    exploitable by any local user who can execute the sudo command without authentication. Successful
    exploitation of this flaw could lead to privilege escalation.  (CVE-2021-3156)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20201105.1045
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7dd4b059");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3156");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sudo Heap-Based Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:ahv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/Node/Version", "Host/Nutanix/Data/Node/Type");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info(node:TRUE);

var constraints = [
  { 'fixed_version' : '20201105.1045', 'product' : 'AHV', 'fixed_display' : 'Upgrade the AHV install to 20201105.1045 or higher.' }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
