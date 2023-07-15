#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3591-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(118590);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2017-16541", "CVE-2018-12376", "CVE-2018-12377", "CVE-2018-12378", "CVE-2018-12379", "CVE-2018-12381", "CVE-2018-12383", "CVE-2018-12385", "CVE-2018-12386", "CVE-2018-12387");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : MozillaFirefox, MozillaFirefox-branding-SLE, llvm4, mozilla-nspr, mozilla-nss, apache2-mod_nss (SUSE-SU-2018:3591-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox to ESR 60.2.2 fixes several issues.

These general changes are part of the version 60 release.

New browser engine with speed improvements

Redesigned graphical user interface elements

Unified address and search bar for new installations

New tab page listing top visited, recently visited and recommended
pages

Support for configuration policies in enterprise deployments via JSON
files

Support for Web Authentication, allowing the use of USB tokens for
authentication to websites

The following changes affect compatibility: Now exclusively supports
extensions built using the WebExtension API.

Unsupported legacy extensions will no longer work in Firefox 60 ESR

TLS certificates issued by Symantec before June 1st, 2016 are no
longer trusted The 'security.pki.distrust_ca_policy' preference can be
set to 0 to reinstate trust in those certificates

The following issues affect performance: new format for storing
private keys, certificates and certificate trust If the user home or
data directory is on a network file system, it is recommended that
users set the following environment variable to avoid slowdowns:
NSS_SDB_USE_CACHE=yes This setting is not recommended for local, fast
file systems.

These security issues were fixed: CVE-2018-12381: Dragging and
dropping Outlook email message results in page navigation
(bsc#1107343).

CVE-2017-16541: Proxy bypass using automount and autofs (bsc#1107343).

CVE-2018-12376: Various memory safety bugs (bsc#1107343).

CVE-2018-12377: Use-after-free in refresh driver timers (bsc#1107343).

CVE-2018-12378: Use-after-free in IndexedDB (bsc#1107343).

CVE-2018-12379: Out-of-bounds write with malicious MAR file
(bsc#1107343).

CVE-2018-12386: Type confusion in JavaScript allowed remote code
execution (bsc#1110506)

CVE-2018-12387: Array.prototype.push stack pointer vulnerability may
enable exploits in the sandboxed content process (bsc#1110507)

CVE-2018-12385: Crash in TransportSecurityInfo due to cached data
(bsc#1109363)

CVE-2018-12383: Setting a master password did not delete unencrypted
previously stored passwords (bsc#1107343)

This update for mozilla-nspr to version 4.19 fixes the follwing issues
Added TCP Fast Open functionality

A socket without PR_NSPR_IO_LAYER will no longer trigger an assertion
when polling

This update for mozilla-nss to version 3.36.4 fixes the follwing
issues Connecting to a server that was recently upgraded to TLS 1.3
would result in a SSL_RX_MALFORMED_SERVER_HELLO error.

Fix a rare bug with PKCS#12 files.

Replaces existing vectorized ChaCha20 code with verified HACL*
implementation.

TLS 1.3 support has been updated to draft -23.

Added formally verified implementations of non-vectorized Chacha20 and
non-vectorized Poly1305 64-bit.

The following CA certificates were Removed: OU = Security
Communication EV RootCA1 CN = CA Disig Root R1 CN = DST ACES CA X6
Certum CA, O=Unizeto Sp. z o.o. StartCom Certification Authority
StartCom Certification Authority G2
T&Atilde;&#131;&Acirc;&#156;B&Atilde;&#132;&Acirc;&deg;TAK UEKAE
K&Atilde;&#131;&Acirc;&para;k Sertifika Hizmet
Sa&Atilde;&#132;&Acirc;&#159;lay&Atilde;&#132;&Acirc;&plusmn;c&Atilde;
&#132;&Acirc;&plusmn;s&Atilde;&#132;&Acirc;&plusmn; -
S&Atilde;&#131;&Acirc;&frac14;r&Atilde;&#131;&Acirc;&frac14;m 3
ACEDICOM Root Certinomis - Autorit&Atilde;&#131;&Acirc;&copy; Racine
T&Atilde;&#131;&Acirc;&#156;RKTRUST Elektronik Sertifika Hizmet
Sa&Atilde;&#132;&Acirc;&#159;lay&Atilde;&#132;&Acirc;&plusmn;c&Atilde;
&#132;&Acirc;&plusmn;s&Atilde;&#132;&Acirc;&plusmn; PSCProcert CA
&Atilde;&brvbar;&Acirc;&sup2;&Acirc;&#131;&Atilde;&copy;&Acirc;&#128;&
Acirc;&#154;&Atilde;&brvbar;&Acirc;&nbsp;&Acirc;&sup1;&Atilde;&uml;&Ac
irc;&macr;&Acirc;&#129;&Atilde;&curren;&Acirc;&sup1;&Acirc;&brvbar;,
O=WoSign CA Limited Certification Authority of WoSign Certification
Authority of WoSign G2 CA WoSign ECC Root Subject CN = VeriSign Class
3 Secure Server CA - G2 O = Japanese Government, OU = ApplicationCA CN
= WellsSecure Public Root Certificate Authority CN =
T&Atilde;&#131;&Acirc;&#156;RKTRUST Elektronik Sertifika Hizmet
Sa&Atilde;&#132;&Acirc;&#159;lay&Atilde;&#132;&Acirc;&plusmn;c&Atilde;
&#132;&Acirc;&plusmn;s&Atilde;&#132;&Acirc;&plusmn; H6 CN = Microsec
e-Szigno Root

The following CA certificates were Removed: AddTrust Public CA Root
AddTrust Qualified CA Root China Internet Network Information Center
EV Certificates Root CNNIC ROOT ComSign Secured CA GeoTrust Global CA
2 Secure Certificate Services Swisscom Root CA 1 Swisscom Root EV CA 2
Trusted Certificate Services UTN-USERFirst-Hardware
UTN-USERFirst-Object

The following CA certificates were Added CN = D-TRUST Root CA 3 2013
CN = TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1 GDCA TrustAUTH R5
ROOT SSL.com Root Certification Authority RSA SSL.com Root
Certification Authority ECC SSL.com EV Root Certification Authority
RSA R2 SSL.com EV Root Certification Authority ECC TrustCor RootCert
CA-1 TrustCor RootCert CA-2 TrustCor ECA-1

The Websites (TLS/SSL) trust bit was turned off for the following CA
certificates: CN = Chambers of Commerce Root CN = Global Chambersign
Root

TLS servers are able to handle a ClientHello statelessly, if the
client supports TLS 1.3. If the server sends a HelloRetryRequest, it
is possible to discard the server socket, and make a new socket to
handle any subsequent ClientHello. This better enables stateless
server operation. (This feature is added in support of QUIC, but it
also has utility for DTLS 1.3 servers.)

Due to the update of mozilla-nss apache2-mod_nss needs to be updated
to change to the SQLite certificate database, which is now the default
(bsc#1108771)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1012260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1021577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1026191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1041469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1041894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1073210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1078436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1094767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1108771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1108986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1110506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1110507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=703591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=839074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=857131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=893359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16541/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12376/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12377/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12378/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12379/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12381/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12383/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12385/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12386/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12387/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183591-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?292c5959"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-2549=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-2549=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-2549=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-2549=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-2549=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-2549=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-2549=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-2549=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-2549=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-2549=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-branding-SLE-60-32.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debuginfo-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debugsource-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-devel-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-translations-common-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"apache2-mod_nss-1.0.14-19.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"apache2-mod_nss-debuginfo-1.0.14-19.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"apache2-mod_nss-debugsource-1.0.14-19.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-hmac-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-hmac-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-hmac-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-hmac-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-32bit-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-debuginfo-32bit-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-debuginfo-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-debugsource-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-devel-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-debugsource-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-devel-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-tools-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-tools-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-branding-SLE-60-32.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-debuginfo-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-debugsource-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-devel-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-translations-common-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-hmac-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-hmac-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-hmac-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-hmac-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-32bit-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-debuginfo-32bit-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-debuginfo-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-debugsource-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-devel-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-debugsource-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-devel-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-tools-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-tools-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-branding-SLE-60-32.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-debuginfo-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-debugsource-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-translations-common-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"apache2-mod_nss-1.0.14-19.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"apache2-mod_nss-debuginfo-1.0.14-19.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"apache2-mod_nss-debugsource-1.0.14-19.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreebl3-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreebl3-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreebl3-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreebl3-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreebl3-hmac-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreebl3-hmac-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsoftokn3-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsoftokn3-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsoftokn3-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsoftokn3-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsoftokn3-hmac-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsoftokn3-hmac-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nspr-32bit-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nspr-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nspr-debuginfo-32bit-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nspr-debuginfo-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nspr-debugsource-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-certs-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-certs-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-certs-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-certs-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-debugsource-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-sysinit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-sysinit-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-sysinit-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-tools-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mozilla-nss-tools-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-branding-SLE-60-32.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-debuginfo-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-debugsource-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-devel-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-translations-common-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"apache2-mod_nss-1.0.14-19.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"apache2-mod_nss-debuginfo-1.0.14-19.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"apache2-mod_nss-debugsource-1.0.14-19.6.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreebl3-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreebl3-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreebl3-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreebl3-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreebl3-hmac-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreebl3-hmac-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsoftokn3-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsoftokn3-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsoftokn3-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsoftokn3-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsoftokn3-hmac-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsoftokn3-hmac-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nspr-32bit-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nspr-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nspr-debuginfo-32bit-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nspr-debuginfo-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nspr-debugsource-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-certs-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-certs-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-certs-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-certs-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-debugsource-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-sysinit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-sysinit-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-sysinit-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-tools-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mozilla-nss-tools-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-branding-SLE-60-32.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-debugsource-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-translations-common-60.2.2esr-109.46.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libfreebl3-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libfreebl3-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libfreebl3-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsoftokn3-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nspr-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nspr-debugsource-4.19-19.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-certs-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-debugsource-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-sysinit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-tools-3.36.4-58.15.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"mozilla-nss-tools-debuginfo-3.36.4-58.15.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-SLE / llvm4 / mozilla-nspr / mozilla-nss / apache2-mod_nss");
}
