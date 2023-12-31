#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-666.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86437);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-8178", "CVE-2014-8179");

  script_name(english:"openSUSE Security Update : docker (openSUSE-2015-666)");
  script_summary(english:"Check for the openSUSE-2015-666 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Docker was updated to 1.8.3 to fix two security issues.

The following vulnerabilities were fixed :

  - CVE-2014-8178: layer IDs lead to local graph poisoning
    (boo#949660)

  - CVE-2014-8179: manifest validation and parsing logic
    errors allow pull-by-digest validation bypass

In addition, the following change is included :

  - --disable-legacy-registry to prevent a daemon from using
    a v1 registry"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949660"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected docker packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"docker-1.8.3-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-bash-completion-1.8.3-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-debuginfo-1.8.3-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-debugsource-1.8.3-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-test-1.8.3-43.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"docker-zsh-completion-1.8.3-43.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-bash-completion / docker-debuginfo / etc");
}
