##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168829);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/05");

  script_cve_id(
    "CVE-2022-3996",
    "CVE-2022-4203",
    "CVE-2022-4304",
    "CVE-2022-4450",
    "CVE-2023-0215",
    "CVE-2023-0216",
    "CVE-2023-0217",
    "CVE-2023-0286",
    "CVE-2023-0401"
  );
  script_xref(name:"IAVA", value:"2022-A-0518-S");

  script_name(english:"OpenSSL 3.0.0 < 3.0.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 3.0.8. It is, therefore, affected by a denial of service
(DoS) vulnerability. If an X.509 certificate contains a malformed policy constraint and policy processing is enabled,
then a write lock will be taken twice recursively. On some operating systems (most widely: Windows) this results in a
denial of service when the affected process hangs. Policy processing being enabled on a publicly facing server is not
considered to be a common setup. Policy processing is enabled by passing the -policy argument to the command line
utilities or by calling either X509_VERIFY_PARAM_add0_policy() or X509_VERIFY_PARAM_set1_policies() functions.

  - There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName.
    X.400 addresses were parsed as an ASN1_STRING but the public structure definition for GENERAL_NAME
    incorrectly specified the type of the x400Address field as ASN1_TYPE. This field is subsequently
    interpreted by the OpenSSL function GENERAL_NAME_cmp as an ASN1_TYPE rather than an ASN1_STRING. When CRL
    checking is enabled (i.e. the application sets the X509_V_FLAG_CRL_CHECK flag), this vulnerability may
    allow an attacker to pass arbitrary pointers to a memcmp call, enabling them to read memory contents or
    enact a denial of service. In most cases, the attack requires the attacker to provide both the certificate
    chain and CRL, neither of which need to have a valid signature. If the attacker only controls one of these
    inputs, the other input must already contain an X.400 address as a CRL distribution point, which is
    uncommon. As such, this vulnerability is most likely to only affect applications which have implemented
    their own functionality for retrieving CRLs over a network. (CVE-2023-0286)

  - If an X.509 certificate contains a malformed policy constraint and policy processing is enabled, then a
    write lock will be taken twice recursively. On some operating systems (most widely: Windows) this results
    in a denial of service when the affected process hangs. Policy processing being enabled on a publicly
    facing server is not considered to be a common setup. Policy processing is enabled by passing the

    `-policy' argument to the command line utilities or by calling the `X509_VERIFY_PARAM_set1_policies()'
    function. Update (31 March 2023): The description of the policy processing enablement was corrected based
    on CVE-2023-0466. (CVE-2022-3996)

  - A read buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed the malicious certificate or for the application to continue certificate verification despite
    failure to construct a path to a trusted issuer. The read buffer overrun might result in a crash which
    could lead to a denial of service attack. In theory it could also result in the disclosure of private
    memory contents (such as private keys, or sensitive plaintext) although we are not aware of any working
    exploit leading to memory contents disclosure as of the time of release of this advisory. In a TLS client,
    this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the
    server requests client authentication and a malicious client connects. (CVE-2022-4203)

  - A timing based side channel exists in the OpenSSL RSA Decryption implementation which could be sufficient
    to recover a plaintext across a network in a Bleichenbacher style attack. To achieve a successful
    decryption an attacker would have to be able to send a very large number of trial messages for decryption.
    The vulnerability affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP and RSASVE. For example, in a TLS
    connection, RSA is commonly used by a client to send an encrypted pre-master secret to the server. An
    attacker that had observed a genuine connection between a client and a server could use this flaw to send
    trial messages to the server and record the time taken to process them. After a sufficiently large number
    of messages the attacker could recover the pre-master secret used for the original connection and thus be
    able to decrypt the application data sent over that connection. (CVE-2022-4304)

  - The function PEM_read_bio_ex() reads a PEM file from a BIO and parses and decodes the name (e.g.
    CERTIFICATE), any header data and the payload data. If the function succeeds then the name_out,
    header and data arguments are populated with pointers to buffers containing the relevant decoded data.
    The caller is responsible for freeing those buffers. It is possible to construct a PEM file that results
    in 0 bytes of payload data. In this case PEM_read_bio_ex() will return a failure code but will populate
    the header argument with a pointer to a buffer that has already been freed. If the caller also frees this
    buffer then a double free will occur. This will most likely lead to a crash. This could be exploited by an
    attacker who has the ability to supply malicious PEM files for parsing to achieve a denial of service
    attack. The functions PEM_read_bio() and PEM_read() are simple wrappers around PEM_read_bio_ex() and
    therefore these functions are also directly affected. These functions are also called indirectly by a
    number of other OpenSSL functions including PEM_X509_INFO_read_bio_ex() and SSL_CTX_use_serverinfo_file()
    which are also vulnerable. Some OpenSSL internal uses of these functions are not vulnerable because the
    caller does not free the header argument if PEM_read_bio_ex() returns a failure code. These locations
    include the PEM_read_bio_TYPE() functions as well as the decoders introduced in OpenSSL 3.0. The OpenSSL
    asn1parse command line application is also impacted by this issue. (CVE-2022-4450)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-0401");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20230207.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/policies/secpolicy.html");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-0286");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-0217");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-0216");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-0215");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2022-4450");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2022-4304");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2022-4203");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 3.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0286");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("openssl/port", "installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');


var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [{ 'min_version' : '3.0.0', 'fixed_version' : '3.0.8'}];

vcf::openssl::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);