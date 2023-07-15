#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-176.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106894);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11624", "CVE-2017-11625", "CVE-2017-11626", "CVE-2017-11627", "CVE-2017-12595", "CVE-2017-9208", "CVE-2017-9209", "CVE-2017-9210");

  script_name(english:"openSUSE Security Update : qpdf (openSUSE-2018-176)");
  script_summary(english:"Check for the openSUSE-2018-176 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This version update for qpdf to 7.1.1 fixes the following issues :

  - Update to version 7.1.1

  - Fix one linearization bug affecting files whose first
    /ID component is not 16 bytes long

  - Update to version 7.1.0

  - Allow raw encryption key to be specified in libary and
    command line with the QPDF::setPasswordIsHexKey method
    and

    --password-is-hex-key option. Allow encryption key to be
    displayed with --show-encryption-key option. See
    https://blog.didierstevens.com/2017/12/28/cracking-encry
    pted-pdfs-part-3/ for a discussion of using this for
    cracking encrypted PDFs. I hope that a future release of
    qpdf will include some additional recovery options that
    may also make use of this capability.

  - Fix lexical error: the PDF specification allows floating
    point numbers to end with '.'

  - Fix link order in the build to avoid conflicts when
    building from source while an older version of qpdf is
    installed

  - Add support for TIFF predictor for LZW and Flate
    streams. Now

  - Clarify documentation around options that control
    parsing but not output creation. Two options:
    --suppress-recovery and

    --ignore-xref-streams, were documented in the 'Advanced
    Transformation Options' section of the manual and --help
    output even though they are not related to output. These
    are now described in a separate section called 'Advanced
    Parsing Options.'

  - Implement remaining PNG filters for decode. Prior
    versions could decode only the 'up' filter. Now all PNG
    filters (sub, up, average, Paeth, optimal) are supported
    for decoding. The implementation of the remaining PNG
    filters changed the interface to the private
    Pl_PNGFilter class, but this class's header file is not
    in the installation, and there is no public interface to
    the class. Within the library, the class is never
    allocated on the stack; it is only ever dynamically
    allocated. As such, this does not actually break binary
    compatibility of the library. all predictor functions
    are supported

  - Update to version 7.0.0

  - License is now Apache-2.0

  - Add new libjpeg8-devel dependency

  - Improve the error message that is issued when QPDFWriter
    encounters a stream that can't be decoded. In
    particular, mention that the stream will be copied
    without filtering to avoid data loss.

  - Add new methods to the C API to correspond to new
    additions to QPDFWriter :

    &#9;- qpdf_set_compress_streams

    &#9;- qpdf_set_decode_level

    &#9;- qpdf_set_preserve_unreferenced_objects

    &#9;- qpdf_set_newline_before_endstream

  - Add support for writing PCLm files

  - QPDF now supports reading and writing streams encoded
    with JPEG or RunLength encoding. Library API
    enhancements and command-line options have been added to
    control this behavior. See command-line options
    --compress-streams and --decode-level and methods
    QPDFWriter::setCompressStreams and
    QPDFWriter::setDecodeLevel.

  - Page rotation is now supported and accessible from both
    the library and the command line.

  - Fixes CVE-2017-12595 boo#1055960, CVE-2017-9208
    boo#1040311 CVE-2017-9209 boo#1040312, CVE-2017-9210
    boo#1040313, CVE-2017-11627 boo#1050577, CVE-2017-11626
    boo#1050578, CVE-2017-11625 boo#1050579, CVE-2017-11624
    boo#1050581

  - Update to version 6.0.0

  - Bump shared library version since 5.2.0 broke ABI.

  - Update to version 5.2.0

  - Support for deterministic /IDs for non-encrypted files.
    This is off by default.

  - Handle more invalid xref tables"
  );
  # https://blog.didierstevens.com/2017/12/28/cracking-encrypted-pdfs-part-3/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70db0b82"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055960"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qpdf packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-cups-browsed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-cups-browsed-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-foomatic-rip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-foomatic-rip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqpdf18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqpdf18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qpdf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qpdf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qpdf-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libqpdf18-7.1.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libqpdf18-debuginfo-7.1.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qpdf-7.1.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qpdf-debuginfo-7.1.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qpdf-debugsource-7.1.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qpdf-devel-7.1.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cups-filters-1.8.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cups-filters-cups-browsed-1.8.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cups-filters-cups-browsed-debuginfo-1.8.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cups-filters-debuginfo-1.8.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cups-filters-debugsource-1.8.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cups-filters-devel-1.8.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cups-filters-foomatic-rip-1.8.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cups-filters-foomatic-rip-debuginfo-1.8.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cups-filters-ghostscript-1.8.2-4.2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cups-filters-ghostscript-debuginfo-1.8.2-4.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqpdf18 / libqpdf18-debuginfo / qpdf / qpdf-debuginfo / etc");
}
