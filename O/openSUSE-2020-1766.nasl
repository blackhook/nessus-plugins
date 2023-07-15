#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1766.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(142135);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/03");

  script_cve_id("CVE-2020-15190", "CVE-2020-15191", "CVE-2020-15192", "CVE-2020-15193", "CVE-2020-15194", "CVE-2020-15195", "CVE-2020-15202", "CVE-2020-15203", "CVE-2020-15204", "CVE-2020-15205", "CVE-2020-15206", "CVE-2020-15207", "CVE-2020-15208", "CVE-2020-15209", "CVE-2020-15210", "CVE-2020-15211");

  script_name(english:"openSUSE Security Update : tensorflow2 (openSUSE-2020-1766)");
  script_summary(english:"Check for the openSUSE-2020-1766 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for tensorflow2 fixes the following issues :

  - updated to 2.1.2 with following fixes (boo#1177022) :

  - Fixes an undefined behavior causing a segfault in
    tf.raw_ops.Switch (CVE-2020-15190)

  - Fixes three vulnerabilities in conversion to DLPack
    format (CVE-2020-15191, CVE-2020-15192, CVE-2020-15193)

  - Fixes two vulnerabilities in SparseFillEmptyRowsGrad
    (CVE-2020-15194, CVE-2020-15195)

  - Fixes an integer truncation vulnerability in code using
    the work sharder API (CVE-2020-15202)

  - Fixes a format string vulnerability in
    tf.strings.as_string (CVE-2020-15203)

  - Fixes segfault raised by calling session-only ops in
    eager mode (CVE-2020-15204)

  - Fixes data leak and potential ASLR violation from
    tf.raw_ops.StringNGrams (CVE-2020-15205)

  - Fixes segfaults caused by incomplete SavedModel
    validation (CVE-2020-15206)

  - Fixes a data corruption due to a bug in negative
    indexing support in TFLite (CVE-2020-15207)

  - Fixes a data corruption due to dimension mismatch in
    TFLite (CVE-2020-15208)

  - Fixes several vulnerabilities in TFLite saved model
    format (CVE-2020-15209, CVE-2020-15210, CVE-2020-15211)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177022"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected tensorflow2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow2-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow2-gnu-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow2-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow2-gnu-openmpi2-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_cc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_cc2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_cc2-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_cc2-gnu-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_cc2-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_cc2-gnu-openmpi2-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_framework2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_framework2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_framework2-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_framework2-gnu-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_framework2-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_framework2-gnu-openmpi2-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-lite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-lite-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2_2_1_2-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2_2_1_2-gnu-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2_2_1_2-gnu-hpc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2_2_1_2-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2_2_1_2-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2_2_1_2-gnu-openmpi2-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2_2_1_2-gnu-openmpi2-hpc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2_2_1_2-gnu-openmpi2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/30");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow2-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow2-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow2-gnu-hpc-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow2-gnu-hpc-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow2-gnu-openmpi2-hpc-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow2-gnu-openmpi2-hpc-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow_cc2-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow_cc2-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow_cc2-gnu-hpc-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow_cc2-gnu-hpc-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow_cc2-gnu-openmpi2-hpc-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow_cc2-gnu-openmpi2-hpc-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow_framework2-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow_framework2-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow_framework2-gnu-hpc-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow_framework2-gnu-hpc-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow_framework2-gnu-openmpi2-hpc-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libtensorflow_framework2-gnu-openmpi2-hpc-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2-debugsource-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2-devel-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2-gnu-hpc-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2-gnu-openmpi2-hpc-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2-lite-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2-lite-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2-lite-debugsource-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2-lite-devel-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2_2_1_2-gnu-hpc-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2_2_1_2-gnu-hpc-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2_2_1_2-gnu-hpc-debugsource-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2_2_1_2-gnu-hpc-devel-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2_2_1_2-gnu-openmpi2-hpc-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2_2_1_2-gnu-openmpi2-hpc-debuginfo-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2_2_1_2-gnu-openmpi2-hpc-debugsource-2.1.2-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tensorflow2_2_1_2-gnu-openmpi2-hpc-devel-2.1.2-lp152.7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtensorflow2-gnu-hpc / libtensorflow2-gnu-hpc-debuginfo / etc");
}
