#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-90.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106359);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-3737", "CVE-2018-2562", "CVE-2018-2573", "CVE-2018-2583", "CVE-2018-2590", "CVE-2018-2591", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2645", "CVE-2018-2647", "CVE-2018-2665", "CVE-2018-2668", "CVE-2018-2696", "CVE-2018-2703");

  script_name(english:"openSUSE Security Update : mysql-community-server (openSUSE-2018-90)");
  script_summary(english:"Check for the openSUSE-2018-90 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mysql-community-server to version 5.6.39 fixes several
issues.

These security issues were fixed :

  - CVE-2018-2622: Vulnerability in the subcomponent:
    Server: DDL. Easily exploitable vulnerability allowed
    low privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server (bsc#1076369).

  - CVE-2018-2562: Vulnerability in the subcomponent: Server
    : Partition. Easily exploitable vulnerability allowed
    low privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server as well as unauthorized update,
    insert or delete access to some of MySQL Server
    accessible data (bsc#1076369).

  - CVE-2018-2640: Vulnerability in the subcomponent:
    Server: Optimizer. Easily exploitable vulnerability
    allowed low privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server
    (bsc#1076369).

  - CVE-2018-2665: Vulnerability in the subcomponent:
    Server: Optimizer). Supported versions that are affected
    are 5.5.58 and prior, 5.6.38 and prior and 5.7.20 and
    prior. Easily exploitable vulnerability allowed low
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server (bsc#1076369).

  - CVE-2018-2668: Vulnerability in the subcomponent:
    Server: Optimizer. Easily exploitable vulnerability
    allowed low privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server
    (bsc#1076369).

  - CVE-2018-2696: Vulnerability in the subcomponent: Server
    : Security : Privileges). Supported versions that are
    affected are 5.6.38 and prior and 5.7.20 and prior.
    Easily exploitable vulnerability allowed unauthenticated
    attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server (bsc#1076369).

  - CVE-2018-2583: Vulnerability in the subcomponent: Stored
    Procedure. Easily exploitable vulnerability allowed high
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. While the
    vulnerability is in MySQL Server, attacks may
    significantly impact additional products. Successful
    attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash
    (complete DOS) of MySQL Server (bsc#1076369).

  - CVE-2018-2612: Vulnerability in the subcomponent:
    InnoDB. Easily exploitable vulnerability allowed high
    privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized
    creation, deletion or modification access to critical
    data or all MySQL Server accessible data and
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server
    (bsc#1076369).

  - CVE-2018-2703: Vulnerability in the subcomponent: Server
    : Security : Privileges. Easily exploitable
    vulnerability allowed low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server (bsc#1076369).

  - CVE-2018-2573: Vulnerability in the subcomponent:
    Server: GIS. Easily exploitable vulnerability allowed
    low privileged attacker with network access via multiple
    protocols to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Server (bsc#1076369).

  - CVE-2017-3737: OpenSSL introduced an 'error state'
    mechanism. The intent was that if a fatal error occurred
    during a handshake then OpenSSL would move into the
    error state and would immediately fail if you attempted
    to continue the handshake. This works as designed for
    the explicit handshake functions (SSL_do_handshake(),
    SSL_accept() and SSL_connect()), however due to a bug it
    did not work correctly if SSL_read() or SSL_write() is
    called directly. In that scenario, if the handshake
    fails then a fatal error will be returned in the initial
    function call. If SSL_read()/SSL_write() is subsequently
    called by the application for the same SSL object then
    it will succeed and the data is passed without being
    decrypted/encrypted directly from the SSL/TLS record
    layer. In order to exploit this issue an application bug
    would have to be present that resulted in a call to
    SSL_read()/SSL_write() being issued after having already
    received a fatal error

  - CVE-2018-2647: Vulnerability in the subcomponent:
    Server: Replication. Easily exploitable vulnerability
    allowed high privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server as well
    as unauthorized update, insert or delete access to some
    of MySQL Server accessible data (bsc#1076369).

  - CVE-2018-2591: Vulnerability in the subcomponent: Server
    : Partition. Easily exploitable vulnerability allowed
    high privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server
    (bsc#1076369).

  - CVE-2018-2590: Vulnerability in the subcomponent:
    Server: Performance Schema. Easily exploitable
    vulnerability allowed high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server (bsc#1076369).

  - CVE-2018-2645: Vulnerability in the subcomponent:
    Server: Performance Schema. Easily exploitable
    vulnerability allowed high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized access to critical data or
    complete access to all MySQL Server accessible data
    (bsc#1076369).

For additional details please see
http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-39.html"
  );
  # http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-39.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-39.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076369"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-community-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libmysql56client18-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysql56client18-debuginfo-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysql56client_r18-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-bench-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-bench-debuginfo-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-client-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-client-debuginfo-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-debuginfo-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-debugsource-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-errormessages-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-test-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-test-debuginfo-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-tools-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-tools-debuginfo-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.39-24.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client18-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client18-debuginfo-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmysql56client_r18-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-bench-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-bench-debuginfo-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-client-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-client-debuginfo-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-debuginfo-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-debugsource-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-errormessages-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-test-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-test-debuginfo-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-tools-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mysql-community-server-tools-debuginfo-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.39-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.39-33.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysql56client18-32bit / libmysql56client18 / etc");
}
