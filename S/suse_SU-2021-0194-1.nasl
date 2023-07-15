#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0194-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(145352);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/25");

  script_name(english:"SUSE SLES15 Security Update : stunnel (SUSE-SU-2021:0194-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for stunnel fixes the following issues :

Security issue fixed :

The 'redirect' option was fixed to properly handle 'verifyChain = yes'
(bsc#1177580).

Non-security issues fixed :

Fix startup problem of the stunnel daemon (bsc#1178533)

update to 5.57 :

  - Security bugfixes

  - New features

  - New securityLevel configuration file option.

  - Support for modern PostgreSQL clients

  - TLS 1.3 configuration updated for better compatibility.

  - Bugfixes

  - Fixed a transfer() loop bug.

  - Fixed memory leaks on configuration reloading errors.

  - DH/ECDH initialization restored for client sections.

  - Delay startup with systemd until network is online.

  - A number of testing framework fixes and improvements.

update to 5.56 :

  - Various text files converted to Markdown format.

  - Support for realpath(3) implementations incompatible
    with POSIX.1-2008, such as 4.4BSD or Solaris.

  - Support for engines without PRNG seeding methods (thx to
    Petr Mikhalitsyn).

  - Retry unsuccessful port binding on configuration file
    reload.

  - Thread safety fixes in SSL_SESSION object handling.

  - Terminate clients on exit in the FORK threading model.

Fixup stunnel.conf handling :

  - Remove old static openSUSE provided stunnel.conf.

  - Use upstream stunnel.conf and tailor it for openSUSE
    using sed.

  - Don't show README.openSUSE when installing.

enable /etc/stunnel/conf.d

re-enable openssl.cnf

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178533"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210194-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e86c234"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP2-2021-194=1"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:stunnel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:stunnel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:stunnel-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", reference:"stunnel-5.57-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"stunnel-debuginfo-5.57-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"stunnel-debugsource-5.57-3.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "stunnel");
}
