#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-5d0b4a2b5b.
#

include("compat.inc");

if (description)
{
  script_id(138917);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-14556", "CVE-2020-14562", "CVE-2020-14573", "CVE-2020-14577", "CVE-2020-14581", "CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621");
  script_xref(name:"FEDORA", value:"2020-5d0b4a2b5b");

  script_name(english:"Fedora 32 : 1:java-11-openjdk (2020-5d0b4a2b5b)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"# July 2020 OpenJDK security update for OpenJDK 11 Full release notes:
https://bitly.com/openjdk1108

## Security fixes

  - JDK-8230613: Better ASCII conversions

  - JDK-8231800: Better listing of arrays

  - JDK-8232014: Expand DTD support

  - JDK-8233234: Better Zip Naming

  - JDK-8233239, CVE-2020-14562: Enhance TIFF support

  - JDK-8233255: Better Swing Buttons

  - JDK-8234032: Improve basic calendar services

  - JDK-8234042: Better factory production of certificates

  - JDK-8234418: Better parsing with CertificateFactory

  - JDK-8234836: Improve serialization handling

  - JDK-8236191: Enhance OID processing

  - JDK-8236867, CVE-2020-14573: Enhance Graal interface
    handling

  - JDK-8237117, CVE-2020-14556: Better ForkJoinPool
    behavior

  - JDK-8237592, CVE-2020-14577: Enhance certificate
    verification

  - JDK-8238002, CVE-2020-14581: Better matrix operations

  - JDK-8238013: Enhance String writing

  - JDK-8238804: Enhance key handling process

  - JDK-8238842: AIOOBE in
    GIFImageReader.initializeStringTable

  - JDK-8238843: Enhanced font handing

  - JDK-8238920, CVE-2020-14583: Better Buffer support

  - JDK-8238925: Enhance WAV file playback

  - JDK-8240119, CVE-2020-14593: Less Affine Transformations

  - JDK-8240482: Improved WAV file playback

  - JDK-8241379: Update JCEKS support

  - JDK-8241522: Manifest improved jar headers redux

  - JDK-8242136, CVE-2020-14621: Better XML namespace
    handling

## [JDK-8244167](https://bugs.openjdk.java.net/browse/JDK-8244167):
Removal of Comodo Root CA Certificate

The following expired Comodo root CA certificate was removed from the
`cacerts` keystore: + alias name 'addtrustclass1ca [jdk]'

Distinguished Name: CN=AddTrust Class 1 CA Root, OU=AddTrust TTP
Network, O=AddTrust AB, C=SE

## [JDK-8244166](https://bugs.openjdk.java.net/browse/JDK-8244166):
Removal of DocuSign Root CA Certificate

The following expired DocuSign root CA certificate was removed from
the `cacerts` keystore: + alias name 'keynectisrootca [jdk]'

Distinguished Name: CN=KEYNECTIS ROOT CA, OU=ROOT, O=KEYNECTIS, C=FR

## [JDK-8240191](https://bugs.openjdk.java.net/browse/JDK-8240191):
Allow SunPKCS11 initialization with NSS when external FIPS modules are
present in the Security Modules Database

The SunPKCS11 security provider can now be initialized with NSS when
FIPS-enabled external modules are configured in the Security Modules
Database (NSSDB). Prior to this change, the SunPKCS11 provider would
throw a RuntimeException with the message: 'FIPS flag set for
non-internal module' when such a library was configured for NSS in
non-FIPS mode.

This change allows the JDK to work properly with recent NSS releases
in GNU/Linux operating systems when the system-wide FIPS policy is
turned on.

Further information can be found in
[JDK-8238555](https://bugs.openjdk.java.net/browse/JDK-8238555).

## [JDK-8245077](https://bugs.openjdk.java.net/browse/JDK-8245077):
Default SSLEngine Should Create in Server Role

In JDK 11 and later, `javax.net.ssl.SSLEngine` by default used client
mode when handshaking. As a result, the set of default enabled
protocols may differ to what is expected. `SSLEngine` would usually be
used in server mode. From this JDK release onwards, `SSLEngine` will
default to server mode. The
`javax.net.ssl.SSLEngine.setUseClientMode(boolean mode)` method may be
used to configure the mode.

## [JDK-8242147](https://bugs.openjdk.java.net/browse/JDK-8242147):
New System Properties to Configure the TLS Signature Schemes

Two new System Properties are added to customize the TLS signature
schemes in JDK. `jdk.tls.client.SignatureSchemes` is added for TLS
client side, and `jdk.tls.server.SignatureSchemes` is added for server
side.

Each System Property contains a comma-separated list of supported
signature scheme names specifying the signature schemes that could be
used for the TLS connections.

The names are described in the 'Signature Schemes' section of the

*Java Security Standard Algorithm Names Specification*.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-5d0b4a2b5b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.openjdk.java.net/browse/JDK-8240191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.openjdk.java.net/browse/JDK-8242147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.openjdk.java.net/browse/JDK-8244166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.openjdk.java.net/browse/JDK-8244167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.openjdk.java.net/browse/JDK-8245077"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected 1:java-11-openjdk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14556");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 32", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC32", reference:"java-11-openjdk-11.0.8.10-2.fc32", epoch:"1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:java-11-openjdk");
}
