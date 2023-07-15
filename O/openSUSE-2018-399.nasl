#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-399.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109384);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-10070", "CVE-2014-10071", "CVE-2014-10072", "CVE-2016-10714", "CVE-2017-18205", "CVE-2017-18206", "CVE-2018-1071", "CVE-2018-1083", "CVE-2018-7549");

  script_name(english:"openSUSE Security Update : zsh (openSUSE-2018-399)");
  script_summary(english:"Check for the openSUSE-2018-399 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for zsh fixes the following issues :

  - CVE-2014-10070: environment variable injection could
    lead to local privilege escalation (bnc#1082885)

  - CVE-2014-10071: buffer overflow in exec.c could lead to
    denial of service. (bnc#1082977)

  - CVE-2014-10072: buffer overflow In utils.c when scanning
    very long directory paths for symbolic links.
    (bnc#1082975)

  - CVE-2016-10714: In zsh before 5.3, an off-by-one error
    resulted in undersized buffers that were intended to
    support PATH_MAX characters. (bnc#1083250)

  - CVE-2017-18205: In builtin.c when sh compatibility mode
    is used, a NULL pointer dereference could lead to denial
    of service (bnc#1082998)

  - CVE-2018-1071: exec.c:hashcmd() function vulnerability
    could lead to denial of service. (bnc#1084656)

  - CVE-2018-1083: Autocomplete vulnerability could lead to
    privilege escalation. (bnc#1087026)

  - CVE-2018-7549: In params.c in zsh through 5.4.2, there
    is a crash during a copy of an empty hash table, as
    demonstrated by typeset -p. (bnc#1082991)

  - CVE-2017-18206: buffer overrun in xsymlinks could lead
    to denial of service (bnc#1083002)

  - Autocomplete and REPORTTIME broken (bsc#896914)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=896914"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected zsh packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zsh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zsh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zsh-htmldoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"zsh-5.0.5-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zsh-debuginfo-5.0.5-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zsh-debugsource-5.0.5-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zsh-htmldoc-5.0.5-9.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zsh / zsh-debuginfo / zsh-debugsource / zsh-htmldoc");
}
