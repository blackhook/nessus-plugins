#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1084.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123544);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : ucode-intel (openSUSE-2019-1084)");
  script_summary(english:"Check for the openSUSE-2019-1084 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ucode-intel fixes the following issues :

Updated to the 20190312 bundle release (bsc#1129231)

New Platforms :

  - AML-Y22 H0 6-8e-9/10 0000009e Core Gen8 Mobile

  - WHL-U W0 6-8e-b/d0 000000a4 Core Gen8 Mobile

  - WHL-U V0 6-8e-d/94 000000b2 Core Gen8 Mobile

  - CFL-S P0 6-9e-c/22 000000a2 Core Gen9 Desktop

  - CFL-H R0 6-9e-d/22 000000b0 Core Gen9 Mobile

Updated Platforms :

  - HSX-E/EP Cx/M1 6-3f-2/6f 0000003d->00000041 Core Gen4 X
    series; Xeon E5 v3

  - HSX-EX E0 6-3f-4/80 00000012->00000013 Xeon E7 v3

  - SKX-SP H0/M0/U0 6-55-4/b7 0200004d->0000005a Xeon
    Scalable

  - SKX-D M1 6-55-4/b7 0200004d->0000005a Xeon D-21xx

  - BDX-DE V1 6-56-2/10 00000017->00000019 Xeon D-1520/40

  - BDX-DE V2/3 6-56-3/10 07000013->07000016 Xeon
    D-1518/19/21/27/28/31/33/37/41/48, Pentium
    D1507/08/09/17/19

  - BDX-DE Y0 6-56-4/10 0f000012->0f000014 Xeon
    D-1557/59/67/71/77/81/87

  - BDX-NS A0 6-56-5/10 0e00000a->0e00000c Xeon
    D-1513N/23/33/43/53

  - APL D0 6-5c-9/03 00000032->00000036 Pentium N/J4xxx,
    Celeron N/J3xxx, Atom x5/7-E39xx

  - APL E0 6-5c-a/03 0000000c->00000010 Atom x5/7-E39xx

  - GLK B0 6-7a-1/01 00000028->0000002c Pentium Silver
    N/J5xxx, Celeron N/J4xxx

  - KBL-U/Y H0 6-8e-9/c0 0000008e->0000009a Core Gen7 Mobile

  - CFL-U43e D0 6-8e-a/c0 00000096->0000009e Core Gen8
    Mobile

  - KBL-H/S/E3 B0 6-9e-9/2a 0000008e->0000009a Core Gen7;
    Xeon E3 v6

  - CFL-H/S/E3 U0 6-9e-a/22 00000096->000000aa Core Gen8
    Desktop, Mobile, Xeon E

  - CFL-S B0 6-9e-b/02 0000008e->000000aa Core Gen8

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129231"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ucode-intel package."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ucode-intel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/01");
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

if ( rpm_check(release:"SUSE15.0", reference:"ucode-intel-20190312-lp150.2.14.1") ) flag++;

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
