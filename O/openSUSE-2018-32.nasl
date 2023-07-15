#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-32.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106061);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-17997", "CVE-2017-5753", "CVE-2018-5334", "CVE-2018-5335", "CVE-2018-5336");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2018-32) (Spectre)");
  script_summary(english:"Check for the openSUSE-2018-32 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wireshark to version 2.2.12 fixes the following 
issues :

  - CVE-2018-5334: IxVeriWave file could crash (boo#1075737)

  - CVE-2018-5335: WCP dissector could crash (boo#1075738)

  - CVE-2018-5336: Multiple dissector crashes (boo#1075739)

  - CVE-2017-17997: MRDISC dissector could crash
    (boo#1074171)

This release no longers enable the Linux kernel BPF JIT compiler via
the net.core.bpf_jit_enable sysctl, as this would make systems more
vulnerable to Spectre variant 1 CVE-2017-5753 - (boo#1075748)

Further bug fixes and updated protocol support as listed in:
https://www.wireshark.org/docs/relnotes/wireshark-2.2.12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.12.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"wireshark-2.2.12-14.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-debuginfo-2.2.12-14.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-debugsource-2.2.12-14.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-devel-2.2.12-14.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-ui-gtk-2.2.12-14.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-ui-gtk-debuginfo-2.2.12-14.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-ui-qt-2.2.12-14.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-ui-qt-debuginfo-2.2.12-14.24.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-2.2.12-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-debuginfo-2.2.12-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-debugsource-2.2.12-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-devel-2.2.12-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-gtk-2.2.12-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-gtk-debuginfo-2.2.12-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-qt-2.2.12-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-qt-debuginfo-2.2.12-32.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-debugsource / etc");
}
