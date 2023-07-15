#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-150-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176498);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/06");

  script_cve_id("CVE-2023-2650");
  script_xref(name:"IAVA", value:"2023-A-0158");

  script_name(english:"Slackware Linux 15.0 / current openssl  Vulnerability (SSA:2023-150-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to openssl.");
  script_set_attribute(attribute:"description", value:
"The version of openssl installed on the remote host is prior to 1.1.1u / 3.1.1. It is, therefore, affected by a
vulnerability as referenced in the SSA:2023-150-01 advisory.

  - Issue summary: Processing some specially crafted ASN.1 object identifiers or data containing them may be
    very slow. Impact summary: Applications that use OBJ_obj2txt() directly, or use any of the OpenSSL
    subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS with no message size limit may experience notable to
    very long delays when processing those messages, which may lead to a Denial of Service. An OBJECT
    IDENTIFIER is composed of a series of numbers - sub-identifiers - most of which have no size limit.
    OBJ_obj2txt() may be used to translate an ASN.1 OBJECT IDENTIFIER given in DER encoding form (using the
    OpenSSL type ASN1_OBJECT) to its canonical numeric text form, which are the sub-identifiers of the OBJECT
    IDENTIFIER in decimal form, separated by periods. When one of the sub-identifiers in the OBJECT IDENTIFIER
    is very large (these are sizes that are seen as absurdly large, taking up tens or hundreds of KiBs), the
    translation to a decimal number in text may take a very long time. The time complexity is O(n^2) with 'n'
    being the size of the sub-identifiers in bytes (*). With OpenSSL 3.0, support to fetch cryptographic
    algorithms using names / identifiers in string form was introduced. This includes using OBJECT IDENTIFIERs
    in canonical numeric text form as identifiers for fetching algorithms. Such OBJECT IDENTIFIERs may be
    received through the ASN.1 structure AlgorithmIdentifier, which is commonly used in multiple protocols to
    specify what cryptographic algorithm should be used to sign or verify, encrypt or decrypt, or digest
    passed data. Applications that call OBJ_obj2txt() directly with untrusted data are affected, with any
    version of OpenSSL. If the use is for the mere purpose of display, the severity is considered low. In
    OpenSSL 3.0 and newer, this affects the subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS. It also impacts
    anything that processes X.509 certificates, including simple things like verifying its signature. The
    impact on TLS is relatively low, because all versions of OpenSSL have a 100KiB limit on the peer's
    certificate chain. Additionally, this only impacts clients, or servers that have explicitly enabled client
    authentication. In OpenSSL 1.1.1 and 1.0.2, this only affects displaying diverse objects, such as X.509
    certificates. This is assumed to not happen in such a way that it would cause a Denial of Service, so
    these versions are considered not affected by this issue in such a way that it would be cause for concern,
    and the severity is therefore considered low. (CVE-2023-2650)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.415918
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?266a9ff5");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected openssl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2650");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:openssl-solibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '1.1.1u', 'product' : 'openssl', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.1.1u', 'product' : 'openssl-solibs', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.1.1u', 'product' : 'openssl', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.1.1u', 'product' : 'openssl-solibs', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '3.1.1', 'product' : 'openssl', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '3.1.1', 'product' : 'openssl-solibs', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '3.1.1', 'product' : 'openssl', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '3.1.1', 'product' : 'openssl-solibs', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
