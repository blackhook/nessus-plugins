#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2079. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127668);
  script_version("1.5");
  script_cvs_date("Date: 2020/01/06");

  script_cve_id("CVE-2018-14598", "CVE-2018-14599", "CVE-2018-14600", "CVE-2018-15853", "CVE-2018-15854", "CVE-2018-15855", "CVE-2018-15856", "CVE-2018-15857", "CVE-2018-15859", "CVE-2018-15861", "CVE-2018-15862", "CVE-2018-15863", "CVE-2018-15864");
  script_xref(name:"RHSA", value:"2019:2079");

  script_name(english:"RHEL 7 : Xorg (RHSA-2019:2079)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for Xorg is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

Security Fix(es) :

* libX11: Crash on invalid reply in XListExtensions in ListExt.c
(CVE-2018-14598)

* libX11: Off-by-one error in XListExtensions in ListExt.c
(CVE-2018-14599)

* libX11: Out of Bounds write in XListExtensions in ListExt.c
(CVE-2018-14600)

* libxkbcommon: Invalid free in ExprAppendMultiKeysymList resulting in
a crash (CVE-2018-15857)

* libxkbcommon: Endless recursion in xkbcomp/expr.c resulting in a
crash (CVE-2018-15853)

* libxkbcommon: NULL pointer dereference resulting in a crash
(CVE-2018-15854)

* libxkbcommon: NULL pointer dereference when handling xkb_geometry
(CVE-2018-15855)

* libxkbcommon: Infinite loop when reaching EOL unexpectedly resulting
in a crash (CVE-2018-15856)

* libxkbcommon: NULL pointer dereference when parsing invalid atoms in
ExprResolveLhs resulting in a crash (CVE-2018-15859)

* libxkbcommon: NULL pointer dereference in ExprResolveLhs resulting
in a crash (CVE-2018-15861)

* libxkbcommon: NULL pointer dereference in LookupModMask resulting in
a crash (CVE-2018-15862)

* libxkbcommon: NULL pointer dereference in ResolveStateAndPredicate
resulting in a crash (CVE-2018-15863)

* libxkbcommon: NULL pointer dereference in resolve_keysym resulting
in a crash (CVE-2018-15864)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3395ff0b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:2079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-14598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-14599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-14600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-15853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-15854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-15855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-15856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-15857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-15859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-15861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-15862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-15863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-15864"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm-pam-extensions-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbcommon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbcommon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbcommon-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbcommon-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libGLw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libGLw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libGLw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-ati");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-ati-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-vesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-vesa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-wacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-wacom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-wacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:2079";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", reference:"gdm-3.28.2-16.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gdm-debuginfo-3.28.2-16.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gdm-devel-3.28.2-16.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gdm-pam-extensions-devel-3.28.2-16.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libX11-1.6.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libX11-common-1.6.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libX11-debuginfo-1.6.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libX11-devel-1.6.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libxkbcommon-0.7.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libxkbcommon-debuginfo-0.7.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libxkbcommon-devel-0.7.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libxkbcommon-x11-0.7.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libxkbcommon-x11-devel-0.7.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libGLw-8.0.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libGLw-debuginfo-8.0.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libGLw-devel-8.0.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-ati-19.0.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-ati-debuginfo-19.0.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-vesa-2.4.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-vesa-debuginfo-2.4.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-wacom-0.36.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-wacom-debuginfo-0.36.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-wacom-debuginfo-0.36.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-wacom-devel-0.36.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-wacom-devel-0.36.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xdmx-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xephyr-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xnest-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xvfb-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xwayland-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xwayland-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-common-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-common-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-server-debuginfo-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-debuginfo-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-debuginfo-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-server-devel-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-devel-1.20.4-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"xorg-x11-server-source-1.20.4-7.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm / gdm-debuginfo / gdm-devel / gdm-pam-extensions-devel / libX11 / etc");
  }
}
