#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-24.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105758);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"openSUSE Security Update : ucode-intel (openSUSE-2018-24) (Spectre)");
  script_summary(english:"Check for the openSUSE-2018-24 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ucode-intel fixes the following issues :

Update to Intel CPU Microcode version 20180108 (boo#1075262)

  - The pre-released microcode fixing some important
    security issues is now officially published (and
    included in the added tarball).

New firmware updates since last version (20170707) are available for
these Intel processors :

  - IVT C0 (06-3e-04:ed) 428->42a

  - SKL-U/Y D0 (06-4e-03:c0) ba->c2

  - BDW-U/Y E/F (06-3d-04:c0) 25->28

  - HSW-ULT Cx/Dx (06-45-01:72) 20->21

  - Crystalwell Cx (06-46-01:32) 17->18

  - BDW-H E/G (06-47-01:22) 17->1b

  - HSX-EX E0 (06-3f-04:80) 0f->10

  - SKL-H/S R0 (06-5e-03:36) ba->c2

  - HSW Cx/Dx (06-3c-03:32) 22->23

  - HSX C0 (06-3f-02:6f) 3a->3b

  - BDX-DE V0/V1 (06-56-02:10) 0f->14

  - BDX-DE V2 (06-56-03:10) 700000d->7000011

  - KBL-U/Y H0 (06-8e-09:c0) 62->80

  - KBL Y0 / CFL D0 (06-8e-0a:c0) 70->80

  - KBL-H/S B0 (06-9e-09:2a) 5e->80

  - CFL U0 (06-9e-0a:22) 70->80

  - CFL B0 (06-9e-0b:02) 72->80

  - SKX H0 (06-55-04:b7) 2000035->200003c

  - GLK B0 (06-7a-01:01) 1e->22"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075262"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ucode-intel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ucode-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ucode-intel-blob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ucode-intel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ucode-intel-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/12");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"ucode-intel-20180108-7.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ucode-intel-blob-20180108-7.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ucode-intel-debuginfo-20180108-7.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ucode-intel-debugsource-20180108-7.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ucode-intel-20180108-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ucode-intel-blob-20180108-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ucode-intel-debuginfo-20180108-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ucode-intel-debugsource-20180108-16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ucode-intel / ucode-intel-blob / ucode-intel-debuginfo / etc");
}
