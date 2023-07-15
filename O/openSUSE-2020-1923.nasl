#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1923.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(142929);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2020-8695", "CVE-2020-8698");

  script_name(english:"openSUSE Security Update : ucode-intel (openSUSE-2020-1923)");
  script_summary(english:"Check for the openSUSE-2020-1923 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ucode-intel fixes the following issues :

  - Intel CPU Microcode updated to 20201027 prerelease 

  - CVE-2020-8695: Fixed Intel RAPL sidechannel attack (SGX)
    (bsc#1170446)

  - CVE-2020-8698: Fixed Fast Store Forward Predictor
    INTEL-SA-00381 (bsc#1173594)

    # New Platforms: | Processor | Stepping | F-M-S/PI | Old
    Ver | New Ver | Products
    |:---------------|:---------|:------------|:---------|:-
    --------|:--------- | TGL | B1 | 06-8c-01/80 | |
    00000068 | Core Gen11 Mobile | CPX-SP | A1 | 06-55-0b/bf
    | | 0700001e | Xeon Scalable Gen3 | CML-H | R1 |
    06-a5-02/20 | | 000000e0 | Core Gen10 Mobile | CML-S62 |
    G1 | 06-a5-03/22 | | 000000e0 | Core Gen10 | CML-S102 |
    Q0 | 06-a5-05/22 | | 000000e0 | Core Gen10 | CML-U62 V2
    | K0 | 06-a6-01/80 | | 000000e0 | Core Gen10 Mobile #
    Updated Platforms: | Processor | Stepping | F-M-S/PI |
    Old Ver | New Ver | Products
    |:---------------|:---------|:------------|:---------|:-
    --------|:--------- | GKL-R | R0 | 06-7a-08/01 |
    00000016 | 00000018 | Pentium J5040/N5030, Celeron
    J4125/J4025/N4020/N4120 | SKL-U/Y | D0 | 06-4e-03/c0 |
    000000d6 | 000000e2 | Core Gen6 Mobile | SKL-U23e | K1 |
    06-4e-03/c0 | 000000d6 | 000000e2 | Core Gen6 Mobile |
    APL | D0 | 06-5c-09/03 | 00000038 | 00000040 | Pentium
    N/J4xxx, Celeron N/J3xxx, Atom x5/7-E39xx | APL | E0 |
    06-5c-0a/03 | 00000016 | 0000001e | Atom x5-E39xx |
    SKL-H/S | R0/N0 | 06-5e-03/36 | 000000d6 | 000000e2 |
    Core Gen6; Xeon E3 v5 | HSX-E/EP | Cx/M1 | 06-3f-02/6f |
    00000043 | 00000044 | Core Gen4 X series; Xeon E5 v3 |
    SKX-SP | B1 | 06-55-03/97 | 01000157 | 01000159 | Xeon
    Scalable | SKX-SP | H0/M0/U0 | 06-55-04/b7 | 02006906 |
    02006a08 | Xeon Scalable | SKX-D | M1 | 06-55-04/b7 |
    02006906 | 02006a08 | Xeon D-21xx | CLX-SP | B0 |
    06-55-06/bf | 04002f01 | 04003003 | Xeon Scalable Gen2 |
    CLX-SP | B1 | 06-55-07/bf | 05002f01 | 05003003 | Xeon
    Scalable Gen2 | ICL-U/Y | D1 | 06-7e-05/80 | 00000078 |
    000000a0 | Core Gen10 Mobile | AML-Y22 | H0 |
    06-8e-09/10 | 000000d6 | 000000de | Core Gen8 Mobile |
    KBL-U/Y | H0 | 06-8e-09/c0 | 000000d6 | 000000de | Core
    Gen7 Mobile | CFL-U43e | D0 | 06-8e-0a/c0 | 000000d6 |
    000000e0 | Core Gen8 Mobile | WHL-U | W0 | 06-8e-0b/d0 |
    000000d6 | 000000de | Core Gen8 Mobile | AML-Y42 | V0 |
    06-8e-0c/94 | 000000d6 | 000000de | Core Gen10 Mobile |
    CML-Y42 | V0 | 06-8e-0c/94 | 000000d6 | 000000de | Core
    Gen10 Mobile | WHL-U | V0 | 06-8e-0c/94 | 000000d6 |
    000000de | Core Gen8 Mobile | KBL-G/H/S/E3 | B0 |
    06-9e-09/2a | 000000d6 | 000000de | Core Gen7; Xeon E3
    v6 | CFL-H/S/E3 | U0 | 06-9e-0a/22 | 000000d6 | 000000de
    | Core Gen8 Desktop, Mobile, Xeon E | CFL-S | B0 |
    06-9e-0b/02 | 000000d6 | 000000de | Core Gen8 | CFL-H/S
    | P0 | 06-9e-0c/22 | 000000d6 | 000000de | Core Gen9 |
    CFL-H | R0 | 06-9e-0d/22 | 000000d6 | 000000de | Core
    Gen9 Mobile | CML-U62 | A0 | 06-a6-00/80 | 000000ca |
    000000e0 | Core Gen10 Mobile

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173594"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected ucode-intel package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ucode-intel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");
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

if ( rpm_check(release:"SUSE15.2", reference:"ucode-intel-20201027-lp152.2.4.1") ) flag++;

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
