#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0026.
#

include("compat.inc");

if (description)
{
  script_id(137739);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2017-5715", "CVE-2019-0117", "CVE-2019-11135", "CVE-2019-11139", "CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");

  script_name(english:"OracleVM 3.3 / 3.4 : microcode_ctl (OVMSA-2020-0026) (Spectre)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - update 06-2d-07 to 0x71a

  - update 06-55-04 to 0x2006906

  - update 06-55-07 to 0x5002f01

  - merge Oracle changes for early load via dracut

  - enable late load on install for UEK4 kernels marked safe
    (except BDW-79)

  - set early_microcode='no' in virtualized guests to avoid
    early load bugs [Orabug: 30618737]

  - Update Intel CPU microcode to microcode-20200602
    release, addresses CVE-2020-0543, CVE-2020-0548,
    CVE-2020-0549 (#1795353, #1795357, #1827186) :

  - Update of 06-3c-03/0x32 (HSW C0) microcode from revision
    0x27 up to 0x28 

  - Update of 06-3d-04/0xc0 (BDW-U/Y E0/F0) microcode from
    revision 0x2e up to 0x2f 

  - Update of 06-45-01/0x72 (HSW-U C0/D0) microcode from
    revision 0x25 up to 0x26 

  - Update of 06-46-01/0x32 (HSW-H C0) microcode from
    revision 0x1b up to 0x1c 

  - Update of 06-47-01/0x22 (BDW-H/Xeon E3 E0/G0) microcode
    from revision 0x21 up to 0x22 

  - Update of 06-4e-03/0xc0 (SKL-U/Y D0) microcode from
    revision 0xd6 up to 0xdc 

  - Update of 06-55-03/0x97 (SKX-SP B1) microcode from
    revision 0x1000151 up to 0x1000157 

  - Update of 06-55-04/0xb7 (SKX-SP H0/M0/U0, SKX-D M1)
    microcode (in intel-06-55-04/intel-ucode/06-55-04) from
    revision 0x2000065 up to 0x2006906 

  - Update of 06-55-06/0xbf (CLX-SP B0) microcode from
    revision 0x400002c up to 0x4002f01 

  - Update of 06-55-07/0xbf (CLX-SP B1) microcode from
    revision 0x500002c up to 0x5002f01 

  - Update of 06-5e-03/0x36 (SKL-H/S R0/N0) microcode from
    revision 0xd6 up to 0xdc 

  - Update of 06-8e-09/0x10 (AML-Y22 H0) microcode from
    revision 0xca up to 0xd6 

  - Update of 06-8e-09/0xc0 (KBL-U/Y H0) microcode from
    revision 0xca up to 0xd6 

  - Update of 06-8e-0a/0xc0 (CFL-U43e D0) microcode from
    revision 0xca up to 0xd6 

  - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode from
    revision 0xca up to 0xd6 

  - Update of 06-8e-0c/0x94 (AML-Y42 V0, CML-Y42 V0, WHL-U
    V0) microcode from revision 0xca up to 0xd6 

  - Update of 06-9e-09/0x2a (KBL-G/H/S/X/Xeon E3 B0)
    microcode from revision 0xca up to 0xd6 

  - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E3 U0) microcode
    from revision 0xca up to 0xd6 

  - Update of 06-9e-0b/0x02 (CFL-S B0) microcode from
    revision 0xca up to 0xd6 

  - Update of 06-9e-0c/0x22 (CFL-H/S P0) microcode from
    revision 0xca up to 0xd6 

  - Update of 06-9e-0d/0x22 (CFL-H R0) microcode from
    revision 0xca up to 0xd6.

  - Update Intel CPU microcode to microcode-20200520 release
    (#1839193) :

  - Update of 06-2d-06/0x6d (SNB-E/EN/EP C1/M0) microcode
    from revision 0x61f up to 0x621 

  - Update of 06-2d-07/0x6d (SNB-E/EN/EP C2/M1) microcode
    from revision 0x718 up to 0x71a 

  - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from
    revision 0x46 up to 0x78.

  - Narrow down SKL-SP/W/X blacklist to exclude
    Server/FPGA/Fabric segment models (#1835555).

  - Do not update 06-55-04 (SKL-SP/W/X) to revision
    0x2000065, use 0x2000064 by default (#1774635).

  - Update Intel CPU microcode to microcode-20191115 
release :

  - Update of 06-4e-03/0xc0 (SKL-U/Y D0) from revision 0xd4
    up to 0xd6 

  - Update of 06-5e-03/0x36 (SKL-H/S/Xeon E3 R0/N0) from
    revision 0xd4 up to 0xd6 

  - Update of 06-8e-09/0x10 (AML-Y 2+2 H0) from revision
    0xc6 up to 0xca 

  - Update of 06-8e-09/0xc0 (KBL-U/Y H0) from revision 0xc6
    up to 0xca 

  - Update of 06-8e-0a/0xc0 (CFL-U 4+3e D0) from revision
    0xc6 up to 0xca 

  - Update of 06-8e-0b/0xd0 (WHL-U W0) from revision 0xc6 up
    to 0xca 

  - Update of 06-8e-0c/0x94 (AML-Y V0, CML-U 4+2 V0, WHL-U
    V0) from revision 0xc6 up to 0xca 

  - Update of 06-9e-09/0x2a (KBL-G/X H0, KBL-H/S/Xeon E3 B0)
    from revision 0xc6 up to 0xca 

  - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) from
    revision 0xc6 up to 0xca 

  - Update of 06-9e-0b/0x02 (CFL-S B0) from revision 0xc6 up
    to 0xca 

  - Update of 06-9e-0c/0x22 (CFL-S/Xeon E P0) from revision
    0xc6 up to 0xca 

  - Update of 06-9e-0d/0x22 (CFL-H/S R0) from revision 0xc6
    up to 0xca 

  - Update of 06-a6-00/0x80 (CML-U 6+2 A0) from revision
    0xc6 up to 0xca.

  - Update Intel CPU microcode to microcode-20191113 
release :

  - Update of 06-9e-0c (CFL-H/S P0) microcode from revision
    0xae up to 0xc6.

  - Drop 0001-releasenote-changes-summary-fixes.patch.

  - Package the publicy available microcode-20191112 release
    (#1755021) :

  - Addition of 06-4d-08/0x1 (AVN B0/C0) microcode at
    revision 0x12d 

  - Addition of 06-55-06/0xbf (CSL-SP B0) microcode at
    revision 0x400002c 

  - Addition of 06-7a-08/0x1 (GLK R0) microcode at revision
    0x16 

  - Update of 06-55-03/0x97 (SKL-SP B1) microcode from
    revision 0x1000150 up to 0x1000151 

  - Update of 06-55-04/0xb7 (SKL-SP H0/M0/U0, SKL-D M1)
    microcode from revision 0x2000064 up to 0x2000065 

  - Update of 06-55-07/0xbf (CSL-SP B1) microcode from
    revision 0x500002b up to 0x500002c 

  - Update of 06-7a-01/0x1 (GLK B0) microcode from revision
    0x2e up to 0x32 

  - Include 06-9e-0c (CFL-H/S P0) microcode from the
    microcode-20190918 release.

  - Correct the releasenote file
    (0001-releasenote-changes-summary-fixes.patch).

  - Update README.caveats with the link to the new Knowledge
    Base article.

  - Fix the incorrect 'Source2:' tag.

  - Intel CPU microcode update to 20191112, addresses
    CVE-2017-5715, CVE-2019-0117, CVE-2019-11135,
    CVE-2019-11139 (#1764049, #1764062, #1764953,

  - Addition of 06-a6-00/0x80 (CML-U 6+2 A0) microcode at
    revision 0xc6 

  - Addition of 06-66-03/0x80 (CNL-U D0) microcode at
    revision 0x2a 

  - Addition of 06-55-03/0x97 (SKL-SP B1) microcode at
    revision 0x1000150 

  - Addition of 06-7e-05/0x80 (ICL-U/Y D1) microcode at
    revision 0x46 

  - Update of 06-4e-03/0xc0 (SKL-U/Y D0) microcode from
    revision 0xcc to 0xd4 

  - Update of 06-5e-03/0x36 (SKL-H/S/Xeon E3 R0/N0)
    microcode from revision 0xcc to 0xd4

  - Update of 06-8e-09/0x10 (AML-Y 2+2 H0) microcode from
    revision 0xb4 to 0xc6 

  - Update of 06-8e-09/0xc0 (KBL-U/Y H0) microcode from
    revision 0xb4 to 0xc6 

  - Update of 06-8e-0a/0xc0 (CFL-U 4+3e D0) microcode from
    revision 0xb4 to 0xc6 

  - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode from
    revision 0xb8 to 0xc6 

  - Update of 06-8e-0c/0x94 (AML-Y V0) microcode from
    revision 0xb8 to 0xc6 

  - Update of 06-8e-0c/0x94 (CML-U 4+2 V0) microcode from
    revision 0xb8 to 0xc6 

  - Update of 06-8e-0c/0x94 (WHL-U V0) microcode from
    revision 0xb8 to 0xc6 

  - Update of 06-9e-09/0x2a (KBL-G/X H0) microcode from
    revision 0xb4 to 0xc6 

  - Update of 06-9e-09/0x2a (KBL-H/S/Xeon E3 B0) microcode
    from revision 0xb4 to 0xc6 

  - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode
    from revision 0xb4 to 0xc6 

  - Update of 06-9e-0b/0x02 (CFL-S B0) microcode from
    revision 0xb4 to 0xc6 

  - Update of 06-9e-0d/0x22 (CFL-H R0) microcode from
    revision 0xb8 to 0xc6.

  - Do not update 06-2d-07 (SNB-E/EN/EP) to revision 0x718,
    use 0x714 by default (#1758382).

  - Revert more strict model check code, as it requires
    request_firmware-based microcode loading mechanism and
    breaks enabling of microcode with caveats.

  - Intel CPU microcode update to 20190918 (#1753540).

  - Intel CPU microcode update to 20190618 (#1717238).

  - Remove disclaimer, as it is not as important now to
    justify kmsg/log pollution  its contents are partially
    adopted in README.caveats.

  - Intel CPU microcode update to 20190514a (#1711938).

  - Intel CPU microcode update to 20190507_Public_DEMO
    (#1697960).

  - Intel CPU microcode update to 20190312 (#1697960).

  - Fix disclaimer path in %post script.

  - Fix installation path for the disclaimer file.

  - Add README.caveats documentation file.

  - Use check_caveats from the RHEL 7 package in order to
    support overrides.

  - Disable 06-4f-01 microcode in config (#1622180).

  - Intel CPU microcode update to 20180807a (#1614427).

  - Add check for minimal microcode version to
    reload_microcode.

  - Intel CPU microcode update to 20180807.

  - Resolves: #1614427.

  - Intel CPU microcode update to 20180703

  - Add infrastructure for handling kernel-version-dependant
    microcode

  - Resolves: #1574593

  - Intel CPU microcode update to 20180613.

  - Resolves: #1573451

  - Update AMD microcode to 2018-05-24

  - Resolves: #1584192

  - Update AMD microcode

  - Resolves: #1574591

  - Update disclaimer text

  - Resolves: #1574588

  - Intel CPU microcode update to 20180425.

  - Resolves: #1574588

  - Revert Microcode from Intel and AMD for Side Channel
    attack

  - Resolves: #1533941

  - Update microcode data file to 20180108 revision.

  - Resolves: #1527354

  - Update Intel CPU microde for 06-3f-02, 06-4f-01, and
    06-55-04

  - Add amd microcode_amd_fam17h.bin data file

  - Resolves: #1527354

  - Update microcode data file to 20170707 revision.

  - Resolves: #1465143

  - Revert microcode_amd_fam15h.bin to version from
    amd-ucode-2012-09-10

  - Resolves: #1322525

  - Update microcode data file to 20161104 revision.

  - Add workaround for E5-26xxv4

  - Resolves: #1346045

  - Update microcode data file to 20160714 revision.

  - Resolves: #1346045

  - Update amd microcode data file to amd-ucode-2013-11-07

  - Resolves: #1322525

  - Update microcode data file to 20151106 revision.

  - Resolves: #1244968

  - Remove bad file permissions on
    /lib/udev/rules.d/89-microcode.rules

  - Resolves: #1201276

  - Update microcode data file to 20150121 revision.

  - Resolves: #1123992

  - Update microcode data file to 20140624 revision.

  - Resolves: #1113394

  - Update microcode data file to 20140430 revision.

  - Resolves: #1036240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2020-June/000988.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2020-June/000986.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected microcode_ctl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0549");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:microcode_ctl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/23");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"microcode_ctl-1.17-33.26.0.1.el6_10")) flag++;

if (rpm_check(release:"OVS3.4", reference:"microcode_ctl-1.17-33.26.0.1.el6_10")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "microcode_ctl");
}
