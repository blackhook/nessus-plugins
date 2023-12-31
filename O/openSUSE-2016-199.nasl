#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-199.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88733);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-8369", "CVE-2015-8377", "CVE-2015-8604", "CVE-2016-2313");

  script_name(english:"openSUSE Security Update : cacti (openSUSE-2016-199)");
  script_summary(english:"Check for the openSUSE-2016-199 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"cacti was updated to fix the following vulnerabilities :

  - CVE-2015-8369: SQL injection in graph.php (boo#958863)

  - CVE-2015-8604: SQL injection in graphs_new.php
    (boo#960678)

  - CVE-2015-8377: SQL injection vulnerability in the
    host_new_graphs_save function in graphs_new.php
    (boo#958977)

  - CVE-2016-2313: Authentication using web authentication
    as a user not in the cacti database allows complete
    access (boo#965930)

The following non-security bugs were fixed :

  - boo#965864: Poller Script Parser was broken

cacti-spine was updated to match the cacti version, fixing a number of
upstream bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965930"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cacti packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"cacti-0.8.8f-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cacti-spine-0.8.8f-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cacti-spine-debuginfo-0.8.8f-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cacti-spine-debugsource-0.8.8f-4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cacti-spine / cacti-spine-debuginfo / cacti-spine-debugsource / etc");
}
