#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-89.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106358);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15369", "CVE-2017-15587", "CVE-2017-17858", "CVE-2017-17866", "CVE-2018-5686");

  script_name(english:"openSUSE Security Update : mupdf (openSUSE-2018-89)");
  script_summary(english:"Check for the openSUSE-2018-89 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mupdf to version 1.12.0 fixes several issues.

These security issues were fixed :

  - CVE-2018-5686: Prevent infinite loop in pdf_parse_array
    function because EOF is not considered. Remote attackers
    could leverage this vulnerability to cause a denial of
    service via a crafted pdf file (bsc#1075936).

  - CVE-2017-15369: The build_filter_chain function in
    pdf/pdf-stream.c mishandled a case where a variable may
    reside in a register, which allowed remote attackers to
    cause a denial of service (Fitz fz_drop_imp
    use-after-free and application crash) or possibly have
    unspecified other impact via a crafted PDF document
    (bsc#1063413).

  - CVE-2017-15587: Prevent integer overflow in
    pdf_read_new_xref_section that allowed for DoS
    (bsc#1064027).

  - CVE-2017-17866: Fixed mishandling of length changes when
    a repair operation occured during a clean operation,
    which allowed remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted PDF
    document (bsc#1074116).

  - CVE-2017-17858: Fixed a heap-based buffer overflow in
    the ensure_solid_xref function which allowed a remote
    attacker to potentially execute arbitrary code via a
    crafted PDF file, because xref subsection object numbers
    were unrestricted (bsc#1077161).

For non-security changes please refer to the changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077161"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mupdf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mupdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mupdf-devel-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.2", reference:"mupdf-1.12.0-13.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mupdf-devel-static-1.12.0-13.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mupdf-1.12.0-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mupdf-devel-static-1.12.0-23.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mupdf / mupdf-devel-static");
}
