#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1883 and 
# CentOS Errata and Security Advisory 2018:1883 respectively.
#

include("compat.inc");

if (description)
{
  script_id(110649);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/10");

  script_cve_id("CVE-2018-1050");
  script_xref(name:"RHSA", value:"2018:1883");

  script_name(english:"CentOS 6 : samba4 (CESA-2018:1883)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for samba4 is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

Security Fix(es) :

* samba: NULL pointer indirection in printer server process
(CVE-2018-1050)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the Samba project for reporting this
issue.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.10 Release Notes and Red Hat Enterprise Linux 6.10
Technical Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-June/005294.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b205960"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected samba4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1050");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"samba4-4.2.10-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-client-4.2.10-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-common-4.2.10-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-dc-4.2.10-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-dc-libs-4.2.10-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-devel-4.2.10-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-libs-4.2.10-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-pidl-4.2.10-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-python-4.2.10-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-test-4.2.10-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-4.2.10-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-clients-4.2.10-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-krb5-locator-4.2.10-15.el6")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba4 / samba4-client / samba4-common / samba4-dc / samba4-dc-libs / etc");
}
