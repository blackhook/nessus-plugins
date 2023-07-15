#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-316.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(146750);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/22");

  script_name(english:"openSUSE Security Update : tor (openSUSE-2021-316)");
  script_summary(english:"Check for the openSUSE-2021-316 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for tor fixes the following issues :

tor was updated to 0.4.5.6 :

- https://lists.torproject.org/pipermail/tor-announce/2021-February/000214.html

  - Introduce a new MetricsPort HTTP interface

  - Support IPv6 in the torrc Address option

  - Add event-tracing library support for USDT and LTTng-UST

  - Try to read N of N bytes on a TLS connection

tor was updated to 0.4.4.7 :

- https://blog.torproject.org/node/1990

  - Stop requiring a live consensus for v3 clients and
    services

  - Re-entry into the network is now denied at the Exit
    level

  - Fix undefined behavior on our Keccak library

  - Strip '\r' characters when reading text files on Unix
    platforms

  - Handle partial SOCKS5 messages correctly

  - Check channels+circuits on relays more thoroughly
    (TROVE-2020-005, boo#1178741)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blog.torproject.org/node/1990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178741"
  );
  # https://lists.torproject.org/pipermail/tor-announce/2021-February/000214.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52835b08"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tor packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"tor-0.4.5.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tor-debuginfo-0.4.5.6-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tor-debugsource-0.4.5.6-lp152.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tor / tor-debuginfo / tor-debugsource");
}
