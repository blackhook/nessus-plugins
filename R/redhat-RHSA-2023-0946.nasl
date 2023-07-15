#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:0946. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(171973);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2022-4203",
    "CVE-2022-4304",
    "CVE-2022-4450",
    "CVE-2023-0215",
    "CVE-2023-0216",
    "CVE-2023-0217",
    "CVE-2023-0286",
    "CVE-2023-0401"
  );
  script_xref(name:"RHSA", value:"2023:0946");
  script_xref(name:"IAVA", value:"2022-A-0518-S");

  script_name(english:"RHEL 9 : openssl (RHSA-2023:0946)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:0946 advisory.

  - openssl: read buffer overflow in X.509 certificate verification (CVE-2022-4203)

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

  - The public API function BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO. It is
    primarily used internally to OpenSSL to support the SMIME, CMS and PKCS7 streaming capabilities, but may
    also be called directly by end user applications. The function receives a BIO from the caller, prepends a
    new BIO_f_asn1 filter BIO onto the front of it to form a BIO chain, and then returns the new head of the
    BIO chain to the caller. Under certain conditions, for example if a CMS recipient public key is invalid,
    the new filter BIO is freed and the function returns a NULL result indicating a failure. However, in this
    case, the BIO chain is not properly cleaned up and the BIO passed by the caller still retains internal
    pointers to the previously freed filter BIO. If the caller then goes on to call BIO_pop() on the BIO then
    a use-after-free will occur. This will most likely result in a crash. This scenario occurs directly in the
    internal function B64_write_ASN1() which may cause BIO_new_NDEF() to be called and will subsequently call
    BIO_pop() on the BIO. This internal function is in turn called by the public API functions
    PEM_write_bio_ASN1_stream, PEM_write_bio_CMS_stream, PEM_write_bio_PKCS7_stream, SMIME_write_ASN1,
    SMIME_write_CMS and SMIME_write_PKCS7. Other public API functions that may be impacted by this include
    i2d_ASN1_bio_stream, BIO_new_CMS, BIO_new_PKCS7, i2d_CMS_bio_stream and i2d_PKCS7_bio_stream. The OpenSSL
    cms and smime command line applications are similarly affected. (CVE-2023-0215)

  - openssl: invalid pointer dereference in d2i_PKCS7 functions (CVE-2023-0216)

  - openssl: NULL dereference validating DSA public key (CVE-2023-0217)

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

  - openssl: NULL dereference during PKCS7 data verification (CVE-2023-0401)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-4203");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-4304");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-4450");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-0215");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-0216");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-0217");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-0286");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-0401");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:0946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2164488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2164497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2164499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2164500");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0286");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 125, 415, 416, 704);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:9.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:9.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel9/9.2/x86_64/appstream/debug',
      'content/aus/rhel9/9.2/x86_64/appstream/os',
      'content/aus/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/aus/rhel9/9.2/x86_64/baseos/debug',
      'content/aus/rhel9/9.2/x86_64/baseos/os',
      'content/aus/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/aarch64/appstream/debug',
      'content/e4s/rhel9/9.2/aarch64/appstream/os',
      'content/e4s/rhel9/9.2/aarch64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/aarch64/baseos/debug',
      'content/e4s/rhel9/9.2/aarch64/baseos/os',
      'content/e4s/rhel9/9.2/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/aarch64/highavailability/debug',
      'content/e4s/rhel9/9.2/aarch64/highavailability/os',
      'content/e4s/rhel9/9.2/aarch64/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/appstream/debug',
      'content/e4s/rhel9/9.2/ppc64le/appstream/os',
      'content/e4s/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/baseos/debug',
      'content/e4s/rhel9/9.2/ppc64le/baseos/os',
      'content/e4s/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/highavailability/debug',
      'content/e4s/rhel9/9.2/ppc64le/highavailability/os',
      'content/e4s/rhel9/9.2/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/resilientstorage/debug',
      'content/e4s/rhel9/9.2/ppc64le/resilientstorage/os',
      'content/e4s/rhel9/9.2/ppc64le/resilientstorage/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/sap-solutions/debug',
      'content/e4s/rhel9/9.2/ppc64le/sap-solutions/os',
      'content/e4s/rhel9/9.2/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/sap/debug',
      'content/e4s/rhel9/9.2/ppc64le/sap/os',
      'content/e4s/rhel9/9.2/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/appstream/debug',
      'content/e4s/rhel9/9.2/s390x/appstream/os',
      'content/e4s/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/baseos/debug',
      'content/e4s/rhel9/9.2/s390x/baseos/os',
      'content/e4s/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/highavailability/debug',
      'content/e4s/rhel9/9.2/s390x/highavailability/os',
      'content/e4s/rhel9/9.2/s390x/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/resilientstorage/debug',
      'content/e4s/rhel9/9.2/s390x/resilientstorage/os',
      'content/e4s/rhel9/9.2/s390x/resilientstorage/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/sap/debug',
      'content/e4s/rhel9/9.2/s390x/sap/os',
      'content/e4s/rhel9/9.2/s390x/sap/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/appstream/debug',
      'content/e4s/rhel9/9.2/x86_64/appstream/os',
      'content/e4s/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/baseos/debug',
      'content/e4s/rhel9/9.2/x86_64/baseos/os',
      'content/e4s/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/highavailability/debug',
      'content/e4s/rhel9/9.2/x86_64/highavailability/os',
      'content/e4s/rhel9/9.2/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/resilientstorage/debug',
      'content/e4s/rhel9/9.2/x86_64/resilientstorage/os',
      'content/e4s/rhel9/9.2/x86_64/resilientstorage/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/sap-solutions/debug',
      'content/e4s/rhel9/9.2/x86_64/sap-solutions/os',
      'content/e4s/rhel9/9.2/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/sap/debug',
      'content/e4s/rhel9/9.2/x86_64/sap/os',
      'content/e4s/rhel9/9.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/appstream/debug',
      'content/eus/rhel9/9.2/aarch64/appstream/os',
      'content/eus/rhel9/9.2/aarch64/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/baseos/debug',
      'content/eus/rhel9/9.2/aarch64/baseos/os',
      'content/eus/rhel9/9.2/aarch64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/codeready-builder/debug',
      'content/eus/rhel9/9.2/aarch64/codeready-builder/os',
      'content/eus/rhel9/9.2/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/highavailability/debug',
      'content/eus/rhel9/9.2/aarch64/highavailability/os',
      'content/eus/rhel9/9.2/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/supplementary/debug',
      'content/eus/rhel9/9.2/aarch64/supplementary/os',
      'content/eus/rhel9/9.2/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/appstream/debug',
      'content/eus/rhel9/9.2/ppc64le/appstream/os',
      'content/eus/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/baseos/debug',
      'content/eus/rhel9/9.2/ppc64le/baseos/os',
      'content/eus/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/debug',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/os',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/highavailability/debug',
      'content/eus/rhel9/9.2/ppc64le/highavailability/os',
      'content/eus/rhel9/9.2/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/resilientstorage/debug',
      'content/eus/rhel9/9.2/ppc64le/resilientstorage/os',
      'content/eus/rhel9/9.2/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/sap-solutions/debug',
      'content/eus/rhel9/9.2/ppc64le/sap-solutions/os',
      'content/eus/rhel9/9.2/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/sap/debug',
      'content/eus/rhel9/9.2/ppc64le/sap/os',
      'content/eus/rhel9/9.2/ppc64le/sap/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/supplementary/debug',
      'content/eus/rhel9/9.2/ppc64le/supplementary/os',
      'content/eus/rhel9/9.2/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/appstream/debug',
      'content/eus/rhel9/9.2/s390x/appstream/os',
      'content/eus/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/baseos/debug',
      'content/eus/rhel9/9.2/s390x/baseos/os',
      'content/eus/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/codeready-builder/debug',
      'content/eus/rhel9/9.2/s390x/codeready-builder/os',
      'content/eus/rhel9/9.2/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/highavailability/debug',
      'content/eus/rhel9/9.2/s390x/highavailability/os',
      'content/eus/rhel9/9.2/s390x/highavailability/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/resilientstorage/debug',
      'content/eus/rhel9/9.2/s390x/resilientstorage/os',
      'content/eus/rhel9/9.2/s390x/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/sap/debug',
      'content/eus/rhel9/9.2/s390x/sap/os',
      'content/eus/rhel9/9.2/s390x/sap/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/supplementary/debug',
      'content/eus/rhel9/9.2/s390x/supplementary/os',
      'content/eus/rhel9/9.2/s390x/supplementary/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/appstream/debug',
      'content/eus/rhel9/9.2/x86_64/appstream/os',
      'content/eus/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/baseos/debug',
      'content/eus/rhel9/9.2/x86_64/baseos/os',
      'content/eus/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/debug',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/os',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/highavailability/debug',
      'content/eus/rhel9/9.2/x86_64/highavailability/os',
      'content/eus/rhel9/9.2/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/resilientstorage/debug',
      'content/eus/rhel9/9.2/x86_64/resilientstorage/os',
      'content/eus/rhel9/9.2/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/sap-solutions/debug',
      'content/eus/rhel9/9.2/x86_64/sap-solutions/os',
      'content/eus/rhel9/9.2/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/sap/debug',
      'content/eus/rhel9/9.2/x86_64/sap/os',
      'content/eus/rhel9/9.2/x86_64/sap/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/supplementary/debug',
      'content/eus/rhel9/9.2/x86_64/supplementary/os',
      'content/eus/rhel9/9.2/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openssl-3.0.1-47.el9_1', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openssl-devel-3.0.1-47.el9_1', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openssl-libs-3.0.1-47.el9_1', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openssl-perl-3.0.1-47.el9_1', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9/aarch64/appstream/debug',
      'content/dist/rhel9/9/aarch64/appstream/os',
      'content/dist/rhel9/9/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9/aarch64/baseos/debug',
      'content/dist/rhel9/9/aarch64/baseos/os',
      'content/dist/rhel9/9/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9/aarch64/codeready-builder/os',
      'content/dist/rhel9/9/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/aarch64/highavailability/debug',
      'content/dist/rhel9/9/aarch64/highavailability/os',
      'content/dist/rhel9/9/aarch64/highavailability/source/SRPMS',
      'content/dist/rhel9/9/aarch64/supplementary/debug',
      'content/dist/rhel9/9/aarch64/supplementary/os',
      'content/dist/rhel9/9/aarch64/supplementary/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/appstream/debug',
      'content/dist/rhel9/9/ppc64le/appstream/os',
      'content/dist/rhel9/9/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/baseos/debug',
      'content/dist/rhel9/9/ppc64le/baseos/os',
      'content/dist/rhel9/9/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/highavailability/debug',
      'content/dist/rhel9/9/ppc64le/highavailability/os',
      'content/dist/rhel9/9/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/sap-solutions/debug',
      'content/dist/rhel9/9/ppc64le/sap-solutions/os',
      'content/dist/rhel9/9/ppc64le/sap-solutions/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/sap/debug',
      'content/dist/rhel9/9/ppc64le/sap/os',
      'content/dist/rhel9/9/ppc64le/sap/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/supplementary/debug',
      'content/dist/rhel9/9/ppc64le/supplementary/os',
      'content/dist/rhel9/9/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel9/9/s390x/appstream/debug',
      'content/dist/rhel9/9/s390x/appstream/os',
      'content/dist/rhel9/9/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9/s390x/baseos/debug',
      'content/dist/rhel9/9/s390x/baseos/os',
      'content/dist/rhel9/9/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9/s390x/codeready-builder/debug',
      'content/dist/rhel9/9/s390x/codeready-builder/os',
      'content/dist/rhel9/9/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/s390x/highavailability/debug',
      'content/dist/rhel9/9/s390x/highavailability/os',
      'content/dist/rhel9/9/s390x/highavailability/source/SRPMS',
      'content/dist/rhel9/9/s390x/resilientstorage/debug',
      'content/dist/rhel9/9/s390x/resilientstorage/os',
      'content/dist/rhel9/9/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/s390x/sap/debug',
      'content/dist/rhel9/9/s390x/sap/os',
      'content/dist/rhel9/9/s390x/sap/source/SRPMS',
      'content/dist/rhel9/9/s390x/supplementary/debug',
      'content/dist/rhel9/9/s390x/supplementary/os',
      'content/dist/rhel9/9/s390x/supplementary/source/SRPMS',
      'content/dist/rhel9/9/x86_64/appstream/debug',
      'content/dist/rhel9/9/x86_64/appstream/os',
      'content/dist/rhel9/9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9/x86_64/baseos/debug',
      'content/dist/rhel9/9/x86_64/baseos/os',
      'content/dist/rhel9/9/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9/x86_64/codeready-builder/os',
      'content/dist/rhel9/9/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/x86_64/highavailability/debug',
      'content/dist/rhel9/9/x86_64/highavailability/os',
      'content/dist/rhel9/9/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9/x86_64/nfv/debug',
      'content/dist/rhel9/9/x86_64/nfv/os',
      'content/dist/rhel9/9/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9/x86_64/resilientstorage/os',
      'content/dist/rhel9/9/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/x86_64/rt/debug',
      'content/dist/rhel9/9/x86_64/rt/os',
      'content/dist/rhel9/9/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9/x86_64/sap-solutions/debug',
      'content/dist/rhel9/9/x86_64/sap-solutions/os',
      'content/dist/rhel9/9/x86_64/sap-solutions/source/SRPMS',
      'content/dist/rhel9/9/x86_64/sap/debug',
      'content/dist/rhel9/9/x86_64/sap/os',
      'content/dist/rhel9/9/x86_64/sap/source/SRPMS',
      'content/dist/rhel9/9/x86_64/supplementary/debug',
      'content/dist/rhel9/9/x86_64/supplementary/os',
      'content/dist/rhel9/9/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openssl-3.0.1-47.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openssl-devel-3.0.1-47.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openssl-libs-3.0.1-47.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openssl-perl-3.0.1-47.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp']) && !enterprise_linux_flag) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl / openssl-devel / openssl-libs / openssl-perl');
}
