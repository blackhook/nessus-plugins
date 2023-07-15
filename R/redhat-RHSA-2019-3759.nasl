#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3759. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130745);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-13699",
    "CVE-2019-13700",
    "CVE-2019-13701",
    "CVE-2019-13702",
    "CVE-2019-13703",
    "CVE-2019-13704",
    "CVE-2019-13705",
    "CVE-2019-13706",
    "CVE-2019-13707",
    "CVE-2019-13708",
    "CVE-2019-13709",
    "CVE-2019-13710",
    "CVE-2019-13711",
    "CVE-2019-13713",
    "CVE-2019-13714",
    "CVE-2019-13715",
    "CVE-2019-13716",
    "CVE-2019-13717",
    "CVE-2019-13718",
    "CVE-2019-13719"
  );
  script_xref(name:"RHSA", value:"2019:3759");

  script_name(english:"RHEL 6 : chromium-browser (RHSA-2019:3759)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for chromium-browser is now available for Red Hat Enterprise
Linux 6 Supplementary.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Chromium is an open source web browser, powered by WebKit (Blink).

This update upgrades Chromium to version 78.0.3904.70.

Security Fix(es) :

* chromium-browser: Use-after-free in media (CVE-2019-13699)

* chromium-browser: Buffer overrun in Blink (CVE-2019-13700)

* chromium-browser: URL spoof in navigation (CVE-2019-13701)

* chromium-browser: Privilege elevation in Installer (CVE-2019-13702)

* chromium-browser: URL bar spoofing (CVE-2019-13703)

* chromium-browser: CSP bypass (CVE-2019-13704)

* chromium-browser: Extension permission bypass (CVE-2019-13705)

* chromium-browser: Out-of-bounds read in PDFium (CVE-2019-13706)

* chromium-browser: File storage disclosure (CVE-2019-13707)

* chromium-browser: HTTP authentication spoof (CVE-2019-13708)

* chromium-browser: File download protection bypass (CVE-2019-13709)

* chromium-browser: File download protection bypass (CVE-2019-13710)

* chromium-browser: Cross-context information leak (CVE-2019-13711)

* chromium-browser: Cross-origin data leak (CVE-2019-13713)

* chromium-browser: CSS injection (CVE-2019-13714)

* chromium-browser: Address bar spoofing (CVE-2019-13715)

* chromium-browser: Service worker state error (CVE-2019-13716)

* chromium-browser: Notification obscured (CVE-2019-13717)

* chromium-browser: IDN spoof (CVE-2019-13718)

* chromium-browser: Notification obscured (CVE-2019-13719)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3759");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13699");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13700");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13701");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13702");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13703");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13704");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13705");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13706");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13707");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13708");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13709");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13710");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13711");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13713");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13714");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13715");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13716");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13717");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13718");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13719");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium-browser and / or
chromium-browser-debuginfo packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13706");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-13700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3759";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-78.0.3904.70-1.el6_10", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-78.0.3904.70-1.el6_10", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-debuginfo-78.0.3904.70-1.el6_10", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-debuginfo-78.0.3904.70-1.el6_10", allowmaj:TRUE)) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium-browser / chromium-browser-debuginfo");
  }
}
