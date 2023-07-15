#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-996.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102949);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-10791", "CVE-2017-10792", "CVE-2017-12958", "CVE-2017-12959", "CVE-2017-12960", "CVE-2017-12961");

  script_name(english:"openSUSE Security Update : pspp (openSUSE-2017-996)");
  script_summary(english:"Check for the openSUSE-2017-996 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pspp fixes the following issues :

  - CVE-2017-12958: Illegal address access in function
    output_hex() could lead to denial of service or
    unexpected state (boo#1054585) 

  - CVE-2017-12959: Assertion in function dict_add_mrset()
    could lead to denial of service (boo#1054588)

  - CVE-2017-12960: Assertion in function dict_rename_var()
    could lead to denial of service (boo#1054587)

  - CVE-2017-12961: Assertion in function parse_attributes()
    could lead to denial of service (boo#1054586)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054588"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pspp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pspp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pspp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pspp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pspp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"pspp-1.0.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pspp-debuginfo-1.0.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pspp-debugsource-1.0.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pspp-devel-1.0.1-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pspp-1.0.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pspp-debuginfo-1.0.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pspp-debugsource-1.0.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pspp-devel-1.0.1-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pspp / pspp-debuginfo / pspp-debugsource / pspp-devel");
}
