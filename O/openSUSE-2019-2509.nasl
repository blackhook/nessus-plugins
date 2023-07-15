#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2509.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(131063);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/13");

  script_cve_id("CVE-2019-11135", "CVE-2019-11139");

  script_name(english:"openSUSE Security Update : ucode-intel (openSUSE-2019-2509)");
  script_summary(english:"Check for the openSUSE-2019-2509 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ucode-intel fixes the following issues :

  - Updated to 20191112 security release (bsc#1155988)

  - Processor Identifier Version Products

  - Model Stepping F-MO-S/PI Old->New

  - ---- new platforms
    ----------------------------------------

  - CML-U62 A0 6-a6-0/80 000000c6 Core Gen10 Mobile

  - CNL-U D0 6-66-3/80 0000002a Core Gen8 Mobile

  - SKX-SP B1 6-55-3/97 01000150 Xeon Scalable

  - ICL U/Y D1 6-7e-5/80 00000046 Core Gen10 Mobile

  - ---- updated platforms
    ------------------------------------

  - SKL U/Y D0 6-4e-3/c0 000000cc->000000d4 Core Gen6 Mobile

  - SKL H/S/E3 R0/N0 6-5e-3/36 000000cc->000000d4 Core Gen6

  - AML-Y22 H0 6-8e-9/10 000000b4->000000c6 Core Gen8 Mobile

  - KBL-U/Y H0 6-8e-9/c0 000000b4->000000c6 Core Gen7 Mobile

  - CFL-U43e D0 6-8e-a/c0 000000b4->000000c6 Core Gen8
    Mobile

  - WHL-U W0 6-8e-b/d0 000000b8->000000c6 Core Gen8 Mobile

  - AML-Y V0 6-8e-c/94 000000b8->000000c6 Core Gen10 Mobile

  - CML-U42 V0 6-8e-c/94 000000b8->000000c6 Core Gen10
    Mobile

  - WHL-U V0 6-8e-c/94 000000b8->000000c6 Core Gen8 Mobile

  - KBL-G/X H0 6-9e-9/2a 000000b4->000000c6 Core Gen7/Gen8

  - KBL-H/S/E3 B0 6-9e-9/2a 000000b4->000000c6 Core Gen7;
    Xeon E3 v6

  - CFL-H/S/E3 U0 6-9e-a/22 000000b4->000000c6 Core Gen8
    Desktop, Mobile, Xeon E

  - CFL-S B0 6-9e-b/02 000000b4->000000c6 Core Gen8

  - CFL-H R0 6-9e-d/22 000000b8->000000c6 Core Gen9 Mobile

  - Includes security fixes for :

  - CVE-2019-11135: Added feature allowing to disable TSX
    RTM (bsc#1139073)

  - CVE-2019-11139: A CPU microcode only fix for Voltage
    modulation issues (bsc#1141035)

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155988"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ucode-intel package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11135");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ucode-intel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"ucode-intel-20191112-lp151.2.9.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ucode-intel");
}
