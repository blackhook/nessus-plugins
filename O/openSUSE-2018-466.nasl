#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-466.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109879);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-1000041");

  script_name(english:"openSUSE Security Update : librsvg (openSUSE-2018-466)");
  script_summary(english:"Check for the openSUSE-2018-466 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for librsvg fixes the following issues :

  - CVE-2018-1000041: Input validation issue could lead to
    credentials leak. (bsc#1083232)

Update to version 2.40.20 :

  + Except for emergencies, this will be the LAST RELEASE of
    the librsvg-2.40.x series. We are moving to 2.41, which
    is vastly improved over the 2.40 series. The API/ABI
    there remain unchaged, so we strongly encourage you to
    upgrade your sources and binaries to librsvg-2.41.x.

  + bgo#761175 - Allow masks and clips to reuse a node being
    drawn.

  + Don't access the file system when deciding whether to
    load a remote file with a UNC path for a paint server
    (i.e. don't try to load it at all).

  + Vistual Studio: fixed and integrated introspection
    builds, so introspection data is built directly from the
    Visual Studio project (Chun-wei Fan).

  + Visual Studio: We now use HIGHENTROPYVA linker option on
    x64 builds, to enhance the security of built binaries
    (Chun-wei Fan).

  + Fix generation of Vala bindings when compiling in
    read-only source directories (Emmanuele Bassi).

Update to version 2.40.19 :

  + bgo#621088: Using text objects as clipping paths is now
    supported.

  + bgo#587721: Fix rendering of text elements with
    transformations (Massimo).

  + bgo#777833 - Fix memory leaks when an RsvgHandle is
    disposed before being closed (Philip Withnall).

  + bgo#782098 - Don't pass deprecated options to gtk-doc
    (Ting-Wei Lan).

  + bgo#786372 - Fix the default for the 'type' attribute of
    the <style> element.

  + bgo#785276 - Don't crash on single-byte files.

  + bgo#634514: Don't render unknown elements and their
    sub-elements.

  + bgo#777155 - Ignore patterns that have close-to-zero
    dimensions.

  + bgo#634324 - Fix Gaussian blurs with negative scaling.

  + Fix the <switch> element; it wasn't working at all.

  + Fix loading when rsvg_handle_write() is called one byte
    at a time.

  + bgo#787895 - Fix incorrect usage of libxml2. Thanks to
    Nick Wellnhofer for advice on this.

  + Backported the test suite machinery from the master
    branch (Chun-wei Fan, Federico Mena).

  + We now require Pango 1.38.0 or later (released in 2015).

  + We now require libxml2 2.9.0 or later (released in
    2012).

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083232"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected librsvg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-thumbnailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-view");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-view-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Rsvg-2_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/17");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"gdk-pixbuf-loader-rsvg-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gdk-pixbuf-loader-rsvg-debuginfo-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librsvg-2-2-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librsvg-2-2-debuginfo-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librsvg-debugsource-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librsvg-devel-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rsvg-thumbnailer-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rsvg-view-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rsvg-view-debuginfo-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-Rsvg-2_0-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-32bit-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-debuginfo-32bit-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"librsvg-2-2-32bit-2.40.20-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"librsvg-2-2-debuginfo-32bit-2.40.20-15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf-loader-rsvg / gdk-pixbuf-loader-rsvg-32bit / etc");
}
