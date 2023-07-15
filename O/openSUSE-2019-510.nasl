#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-510.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123215);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-3639", "CVE-2018-3640");

  script_name(english:"openSUSE Security Update : ucode-intel (openSUSE-2019-510) (Spectre)");
  script_summary(english:"Check for the openSUSE-2019-510 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ucode-intel fixes the following issues :

The microcode bundles was updated to the 20180703 release

For the listed CPU chipsets this fixes CVE-2018-3640 (Spectre v3a) and
helps mitigating CVE-2018-3639 (Spectre v4) (bsc#1100147 bsc#1087082
bsc#1087083).

More information on:
https://downloadcenter.intel.com/download/27945/Linux-Processor-Microc
ode-Data-File

Following chipsets are fixed in this round :

Model Stepping F-MO-S/PI Old->New

---- updated platforms ------------------------------------

SNB-EP C1 6-2d-6/6d 0000061c->0000061d Xeon E5 SNB-EP C2 6-2d-7/6d
00000713->00000714 Xeon E5 IVT C0 6-3e-4/ed 0000042c->0000042d Xeon E5
v2; Core i7-4960X/4930K/4820K IVT D1 6-3e-7/ed 00000713->00000714 Xeon
E5 v2 HSX-E/EP/4S C0 6-3f-2/6f 0000003c->0000003d Xeon E5 v3 HSX-EX E0
6-3f-4/80 00000011->00000012 Xeon E7 v3 SKX-SP/D/W/X H0 6-55-4/b7
02000043->0200004d Xeon Bronze 31xx, Silver 41xx, Gold 51xx/61xx
Platinum 81xx, D/W-21xx; Core i9-7xxxX BDX-DE A1 6-56-5/10
0e000009->0e00000a Xeon D-15x3N BDX-ML B/M/R0 6-4f-1/ef
0b00002c->0b00002e Xeon E5/E7 v4; Core i7-69xx/68xx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100147"
  );
  # https://downloadcenter.intel.com/download/27945/Linux-Processor-Microcode-Data-File
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6521bf44"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected ucode-intel package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3639");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ucode-intel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"ucode-intel-20180703-lp150.2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ucode-intel");
}
