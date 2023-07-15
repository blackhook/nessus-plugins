#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1007.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138672);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2018-8956", "CVE-2020-11868", "CVE-2020-13817", "CVE-2020-15025");

  script_name(english:"openSUSE Security Update : ntp (openSUSE-2020-1007)");
  script_summary(english:"Check for the openSUSE-2020-1007 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ntp fixes the following issues :

ntp was updated to 4.2.8p15

  - CVE-2020-11868: Fixed an issue which a server mode
    packet with spoofed source address frequently send to
    the client ntpd could have caused denial of service
    (bsc#1169740).

  - CVE-2018-8956: Fixed an issue which could have allowed
    remote attackers to prevent a broadcast client from
    synchronizing its clock with a broadcast NTP server via
    spoofed mode 3 and mode 5 packets (bsc#1171355).

  - CVE-2020-13817: Fixed an issue which an off-path
    attacker with the ability to query time from victim's
    ntpd instance could have modified the victim's clock by
    a limited amount (bsc#1172651).

  - CVE-2020-15025: Fixed an issue which remote attacker
    could have caused denial of service by consuming the
    memory when a CMAC key was used andassociated with a
    CMAC algorithm in the ntp.keys (bsc#1173334).

  - Removed an OpenSSL version warning (bsc#992038 and
    bsc#1125401).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=992038"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13817");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntp-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.2", reference:"ntp-4.2.8p15-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ntp-debuginfo-4.2.8p15-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ntp-debugsource-4.2.8p15-lp152.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-debugsource");
}
