#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1699.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141560);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2017-3136", "CVE-2018-5741", "CVE-2019-6477", "CVE-2020-8616", "CVE-2020-8617", "CVE-2020-8618", "CVE-2020-8619", "CVE-2020-8620", "CVE-2020-8621", "CVE-2020-8622", "CVE-2020-8623", "CVE-2020-8624");

  script_name(english:"openSUSE Security Update : bind (openSUSE-2020-1699)");
  script_summary(english:"Check for the openSUSE-2020-1699 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for bind fixes the following issues :

BIND was upgraded to version 9.16.6 :

Note :

  - bind is now more strict in regards to DNSSEC. If queries
    are not working, check for DNSSEC issues. For instance,
    if bind is used in a namserver forwarder chain, the
    forwarding DNS servers must support DNSSEC.

Fixing security issues :

  - CVE-2020-8616: Further limit the number of queries that
    can be triggered from a request. Root and TLD servers
    are no longer exempt from max-recursion-queries. Fetches
    for missing name server. (bsc#1171740) Address records
    are limited to 4 for any domain.

  - CVE-2020-8617: Replaying a TSIG BADTIME response as a
    request could trigger an assertion failure.
    (bsc#1171740)

  - CVE-2019-6477: Fixed an issue where TCP-pipelined
    queries could bypass the tcp-clients limit
    (bsc#1157051).

  - CVE-2018-5741: Fixed the documentation (bsc#1109160).

  - CVE-2020-8618: It was possible to trigger an INSIST when
    determining whether a record would fit into a TCP
    message buffer (bsc#1172958).

  - CVE-2020-8619: It was possible to trigger an INSIST in
    lib/dns/rbtdb.c:new_reference() with a particular zone
    content and query patterns (bsc#1172958).

  - CVE-2020-8624: 'update-policy' rules of type 'subdomain'
    were incorrectly treated as 'zonesub' rules, which
    allowed keys used in 'subdomain' rules to update names
    outside of the specified subdomains. The problem was
    fixed by making sure 'subdomain' rules are again
    processed as described in the ARM (bsc#1175443).

  - CVE-2020-8623: When BIND 9 was compiled with native
    PKCS#11 support, it was possible to trigger an assertion
    failure in code determining the number of bits in the
    PKCS#11 RSA public key with a specially crafted packet
    (bsc#1175443).

  - CVE-2020-8621: named could crash in certain query
    resolution scenarios where QNAME minimization and
    forwarding were both enabled (bsc#1175443).

  - CVE-2020-8620: It was possible to trigger an assertion
    failure by sending a specially crafted large TCP DNS
    message (bsc#1175443).

  - CVE-2020-8622: It was possible to trigger an assertion
    failure when verifying the response to a TSIG-signed
    request (bsc#1175443).

Other issues fixed :

  - Add engine support to OpenSSL EdDSA implementation.

  - Add engine support to OpenSSL ECDSA implementation.

  - Update PKCS#11 EdDSA implementation to PKCS#11 v3.0.

  - Warn about AXFR streams with inconsistent message IDs.

  - Make ISC rwlock implementation the default again.

  - Fixed issues when using cookie-secrets for AES and SHA2
    (bsc#1161168)

  - Installed the default files in /var/lib/named and
    created chroot environment on systems using
    transactional-updates (bsc#1100369, fate#325524)

  - Fixed an issue where bind was not working in FIPS mode
    (bsc#906079).

  - Fixed dependency issues (bsc#1118367 and bsc#1118368).

  - GeoIP support is now discontinued, now GeoIP2 is
    used(bsc#1156205).

  - Fixed an issue with FIPS (bsc#1128220).

  - The liblwres library is discontinued upstream and is no
    longer included.

  - Added service dependency on NTP to make sure the clock
    is accurate when bind is starts (bsc#1170667,
    bsc#1170713).

  - Reject DS records at the zone apex when loading master
    files. Log but otherwise ignore attempts to add DS
    records at the zone apex via UPDATE.

  - The default value of 'max-stale-ttl' has been changed
    from 1 week to 12 hours.

  - Zone timers are now exported via statistics channel.

  - The 'primary' and 'secondary' keywords, when used as
    parameters for 'check-names', were not processed
    correctly and were being ignored.

  - 'rndc dnstap -roll <value>' did not limit the number of
    saved files to <value>.

  - Add 'rndc dnssec -status' command.

  - Addressed a couple of situations where named could
    crash.

  - Changed /var/lib/named to owner root:named and perms
    rwxrwxr-t so that named, being a/the only member of the
    'named' group has full r/w access yet cannot change
    directories owned by root in the case of a compromized
    named. [bsc#1173307, bind-chrootenv.conf]

  - Added '/etc/bind.keys' to NAMED_CONF_INCLUDE_FILES in
    /etc/sysconfig/named to suppress warning message re
    missing file (bsc#1173983).

  - Removed '-r /dev/urandom' from all invocations of
    rndc-confgen (init/named system/lwresd.init
    system/named.init in vendor-files) as this option is
    deprecated and causes rndc-confgen to fail.
    (bsc#1173311, bsc#1176674, bsc#1170713)

  - /usr/bin/genDDNSkey: Removing the use of the -r option
    in the call of /usr/sbin/dnssec-keygen as BIND now uses
    the random number functions provided by the crypto
    library (i.e., OpenSSL or a PKCS#11 provider) as a
    source of randomness rather than /dev/random. Therefore
    the -r command line option no longer has any effect on
    dnssec-keygen. Leaving the option in genDDNSkey as to
    not break compatibility. Patch provided by Stefan
    Eisenwiener. [bsc#1171313]

  - Put libns into a separate subpackage to avoid file
    conflicts in the libisc subpackage due to different
    sonums (bsc#1176092).

  - Require /sbin/start_daemon: both init scripts, the one
    used in systemd context as well as legacy sysv, make use
    of start_daemon.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/325524"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8624");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbind9-1600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbind9-1600-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbind9-1600-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbind9-1600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns1605");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns1605-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns1605-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns1605-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs1601");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs1601-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs1601-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libirs1601-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisc1606");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisc1606-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisc1606-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisc1606-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccc1600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccc1600-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccc1600-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccc1600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccfg1600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccfg1600-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccfg1600-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libisccfg1600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libns1604");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libns1604-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libns1604-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libns1604-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuv1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuv1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuv1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuv1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysuser-shadow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysuser-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"bind-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bind-chrootenv-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bind-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bind-debugsource-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bind-devel-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bind-utils-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bind-utils-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbind9-1600-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbind9-1600-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdns1605-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdns1605-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libirs-devel-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libirs1601-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libirs1601-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libisc1606-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libisc1606-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libisccc1600-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libisccc1600-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libisccfg1600-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libisccfg1600-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libns1604-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libns1604-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libuv-debugsource-1.18.0-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libuv-devel-1.18.0-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libuv1-1.18.0-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libuv1-debuginfo-1.18.0-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-bind-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysuser-shadow-2.0-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysuser-tools-2.0-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"bind-devel-32bit-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libbind9-1600-32bit-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libbind9-1600-32bit-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libdns1605-32bit-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libdns1605-32bit-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libirs1601-32bit-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libirs1601-32bit-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libisc1606-32bit-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libisc1606-32bit-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libisccc1600-32bit-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libisccc1600-32bit-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libisccfg1600-32bit-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libisccfg1600-32bit-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libns1604-32bit-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libns1604-32bit-debuginfo-9.16.6-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libuv1-32bit-1.18.0-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libuv1-32bit-debuginfo-1.18.0-lp152.4.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chrootenv / bind-debuginfo / bind-debugsource / etc");
}
