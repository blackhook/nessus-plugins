#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0846-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(108747);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-5729", "CVE-2018-5730");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : krb5 (SUSE-SU-2018:0846-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for krb5 provides the following fixes: Security issues
fixed :

  - CVE-2018-5730: DN container check bypass by supplying
    special crafted data (bsc#1083927).

  - CVE-2018-5729: NULL pointer dereference in kadmind or DN
    container check bypass by supplying special crafted data
    (bsc#1083926). Non-security issues fixed :

  - Make it possible for legacy applications (e.g. SAP
    Netweaver) to remain compatible with newer Kerberos.
    System administrators who are experiencing this kind of
    compatibility issues may set the environment variable
    GSSAPI_ASSUME_MECH_MATCH to a non-empty value, and make
    sure the environment variable is visible and effective
    to the application startup script. (bsc#1057662)

  - Fix a GSS failure in legacy applications by not
    indicating deprecated GSS mechanisms in
    gss_indicate_mech() list. (bsc#1081725)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1081725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5729/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5730/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180846-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93893ad7"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-567=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2018-567=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2018-567=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-567=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-567=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-567=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2018-567=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2018-567=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-kdb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-kdb-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-preauth-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-preauth-otp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-preauth-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-preauth-pkinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-32bit-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-client-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-client-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-debuginfo-32bit-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-debugsource-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-doc-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-plugin-kdb-ldap-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-plugin-kdb-ldap-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-plugin-preauth-otp-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-plugin-preauth-otp-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-plugin-preauth-pkinit-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-server-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"krb5-server-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-32bit-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-client-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-client-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-debuginfo-32bit-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-debugsource-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-doc-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-plugin-kdb-ldap-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-plugin-kdb-ldap-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-plugin-preauth-otp-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-plugin-preauth-otp-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-plugin-preauth-pkinit-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-server-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"krb5-server-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"krb5-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"krb5-32bit-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"krb5-client-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"krb5-client-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"krb5-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"krb5-debuginfo-32bit-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"krb5-debugsource-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"krb5-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"krb5-32bit-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"krb5-client-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"krb5-client-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"krb5-debuginfo-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"krb5-debuginfo-32bit-1.12.5-40.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"krb5-debugsource-1.12.5-40.23.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5");
}
