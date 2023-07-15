#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0053.
#

include("compat.inc");

if (description)
{
  script_id(143132);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/25");

  script_cve_id("CVE-2020-8694", "CVE-2020-8695", "CVE-2020-8696", "CVE-2020-8698");

  script_name(english:"OracleVM 3.4 : microcode_ctl (OVMSA-2020-0053)");
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

  - recognize the 'force-intel' file path available on EL7+
    [orabug 31655792]

  - disable live load during %post due to UEK4 rendezvous
    timeouts [orabug 31655792]

  - merge Oracle changes for early load via dracut

  - remove no longer appropriate caveats for 06-2d-07 and
    06-55-04

  - remove other caveat support to be compatible with early
    load logic

  - enable late load on install for UEK4 kernels marked safe
    (except BDW-79)

  - set early_microcode='no' in virtualized guests to avoid
    early load bugs [Orabug: 30618737]

  - Update Intel CPU microcode to microcode-20201027
    release, addresses CVE-2020-8694, CVE-2020-8695,
    CVE-2020-8696, (CVE-2020-8698) (#1893243, #1893238) :

  - Addition of 06-55-0b/0xbf (CPX-SP A1) microcode (in
    microcode.dat) at revision 0x700001e 

  - Addition of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode (in
    microcode.dat) at revision 0x68 

  - Addition of 06-a5-02/0x20 (CML-H R1) microcode (in
    microcode.dat) at revision 0xe0 

  - Addition of 06-a5-03/0x22 (CML-S 6+2 G1) microcode (in
    microcode.dat) at revision 0xe0 

  - Addition of 06-a5-05/0x22 (CML-S 10+2 Q0) microcode (in
    microcode.dat) at revision 0xe0 

  - Addition of 06-a6-01/0x80 (CML-U 6+2 v2 K0) microcode
    (in microcode.dat) at revision 0xe0 

  - Update of 06-4e-03/0xc0 (SKL-U/U 2+3e/Y D0/K1) microcode
    (in microcode-06-4e-03.dat) from revision 0xdc up to
    0xe2 

  - Update of 06-55-04/0xb7 (SKX-D/SP/W/X H0/M0/M1/U0)
    microcode (in microcode-06-55-04.dat) from revision
    0x2006906 up to 0x2006a08 

  - Update of 06-5e-03/0x36 (SKL-H/S/Xeon E3 N0/R0/S0)
    microcode (in microcode-06-5e-03.dat) from revision 0xdc
    up to 0xe2 

  - Update of 06-3f-02/0x6f (HSX-E/EN/EP/EP 4S C0/C1/M1/R2)
    microcode (in microcode.dat) from revision 0x43 up to
    0x44 

  - Update of 06-55-03/0x97 (SKX-SP B1) microcode (in
    microcode.dat) from revision 0x1000157 up to 0x1000159 

  - Update of 06-55-06/0xbf (CLX-SP B0) microcode (in
    microcode.dat) from revision 0x4002f01 up to 0x4003003 

  - Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode (in
    microcode.dat) from revision 0x5002f01 up to 0x5003003 

  - Update of 06-5c-09/0x03 (APL D0) microcode (in
    microcode.dat) from revision 0x38 up to 0x40 

  - Update of 06-5c-0a/0x03 (APL B1/F1) microcode (in
    microcode.dat) from revision 0x16 up to 0x1e 

  - Update of 06-7a-08/0x01 (GLK-R R0) microcode (in
    microcode.dat) from revision 0x16 up to 0x18 

  - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode (in
    microcode.dat) from revision 0x78 up to 0xa0 

  - Update of 06-8e-09/0x10 (AML-Y 2+2 H0) microcode (in
    microcode.dat) from revision 0xd6 up to 0xde 

  - Update of 06-8e-09/0xc0 (KBL-U/U 2+3e/Y H0/J1) microcode
    (in microcode.dat) from revision 0xd6 up to 0xde 

  - Update of 06-8e-0a/0xc0 (CFL-U 4+3e D0, KBL-R Y0)
    microcode (in microcode.dat) from revision 0xd6 up to
    0xe0 

  - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode (in
    microcode.dat) from revision 0xd6 up to 0xde 

  - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0,
    WHL-U V0) microcode (in microcode.dat) from revision
    0xd6 up to 0xde 

  - Update of 06-9e-09/0x2a (KBL-G/H/S/X/Xeon E3 B0)
    microcode (in microcode.dat) from revision 0xd6 up to
    0xde 

  - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode
    (in microcode.dat) from revision 0xd6 up to 0xde 

  - Update of 06-9e-0b/0x02 (CFL-E/H/S B0) microcode (in
    microcode.dat) from revision 0xd6 up to 0xde 

  - Update of 06-9e-0c/0x22 (CFL-H/S/Xeon E P0) microcode
    (in microcode.dat) from revision 0xd6 up to 0xde 

  - Update of 06-9e-0d/0x22 (CFL-H/S/Xeon E R0) microcode
    (in microcode.dat) from revision 0xd6 up to 0xde 

  - Update of 06-a6-00/0x80 (CML-U 6+2 A0) microcode (in
    microcode.dat) from revision 0xca up to 0xe0.

  - Add README file to the documentation directory.

  - Add publicly-sourced codenames list to supply to
    gen_provides.sh  update the latter to handle the
    somewhat different format.

  - Add SUMMARY.intel-ucode file containing metadata
    information from the microcode file headers."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2020-November/001005.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb2bc808"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected microcode_ctl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8694");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:microcode_ctl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"microcode_ctl-1.17-33.31.0.1.el6_10")) flag++;

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
