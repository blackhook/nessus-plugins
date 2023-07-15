#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-14fda1bf85.
#

include("compat.inc");

if (description)
{
  script_id(143137);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2020-8695", "CVE-2020-8696", "CVE-2020-8698");
  script_xref(name:"FEDORA", value:"2020-14fda1bf85");

  script_name(english:"Fedora 31 : 2:microcode_ctl (2020-14fda1bf85)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"  - Update to upstream 2.1-30. 20201110

  - Addition of 06-55-0b/0xbf (CPX-SP A1) microcode at
    revision 0x700001e;

  - Addition of 06-8a-01/0x10 (LKF B2/B3) microcode at
    revision 0x28;

  - Addition of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode at
    revision 0x68;

  - Addition of 06-a5-02/0x20 (CML-H R1) microcode at
    revision 0xe0;

  - Addition of 06-a5-03/0x22 (CML-S 6+2 G1) microcode at
    revision 0xe0;

  - Addition of 06-a5-05/0x22 (CML-S 10+2 Q0) microcode at
    revision 0xe0;

  - Addition of 06-a6-01/0x80 (CML-U 6+2 v2 K0) microcode at
    revision 0xe0;

  - Update of 06-3f-02/0x6f (HSX-E/EN/EP/EP 4S C0/C1/M1/R2)
    microcode from revision 0x43 up to 0x44;

  - Update of 06-4e-03/0xc0 (SKL-U/U 2+3e/Y D0/K1) microcode
    from revision 0xd6 up to 0xe2;

  - Update of 06-55-03/0x97 (SKX-SP B1) microcode from
    revision 0x1000157 up to 0x1000159;

  - Update of 06-55-04/0xb7 (SKX-D/SP/W/X H0/M0/M1/U0)
    microcode from revision 0x2006906 up to 0x2006a08;

  - Update of 06-55-06/0xbf (CLX-SP B0) microcode from
    revision 0x4002f01 up to 0x4003003;

  - Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode
    from revision 0x5002f01 up to 0x5003003;

  - Update of 06-5c-09/0x03 (APL D0) microcode from revision
    0x38 up to 0x40;

  - Update of 06-5c-0a/0x03 (APL B1/F1) microcode from
    revision 0x16 up to 0x1e;

  - Update of 06-5e-03/0x36 (SKL-H/S/Xeon E3 N0/R0/S0)
    microcode from revision 0xd6 up to 0xe2;

  - Update of 06-7a-08/0x01 (GLK-R R0) microcode from
    revision 0x16 up to 0x18;

  - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from
    revision 0x78 up to 0xa0;

  - Update of 06-8e-09/0x10 (AML-Y 2+2 H0) microcode from
    revision 0xd6 up to 0xde;

  - Update of 06-8e-09/0xc0 (KBL-U/U 2+3e/Y H0/J1) microcode
    from revision 0xd6 up to 0xde;

  - Update of 06-8e-0a/0xc0 (CFL-U 4+3e D0, KBL-R Y0)
    microcode from revision 0xd6 up to 0xe0;

  - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode from
    revision 0xd6 up to 0xde;

  - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0,
    WHL-U V0) microcode from revision 0xd6 up to 0xde;

  - Update of 06-9e-09/0x2a (KBL-G/H/S/X/Xeon E3 B0)
    microcode from revision 0xd6 up to 0xde;

  - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode
    from revision 0xd6 up to 0xde;

  - Update of 06-9e-0b/0x02 (CFL-E/H/S B0) microcode from
    revision 0xd6 up to 0xde;

  - Update of 06-9e-0c/0x22 (CFL-H/S/Xeon E P0) microcode
    from revision 0xd6 up to 0xde;

  - Update of 06-9e-0d/0x22 (CFL-H/S/Xeon E R0) microcode
    from revision 0xd6 up to 0xde;

  - Update of 06-a6-00/0x80 (CML-U 6+2 A0) microcode from
    revision 0xca up to 0xe0.

  - Addresses CVE-2020-8695, CVE-2020-8696, CVE-2020-8698

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-14fda1bf85"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected 2:microcode_ctl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:2:microcode_ctl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"microcode_ctl-2.1-39.2.fc31", epoch:"2")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "2:microcode_ctl");
}
