#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2020:1176 and 
# CentOS Errata and Security Advisory 2020:1176 respectively.
#

include("compat.inc");

if (description)
{
  script_id(135352);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/05");

  script_cve_id("CVE-2017-6519");
  script_xref(name:"RHSA", value:"2020:1176");

  script_name(english:"CentOS 7 : avahi (CESA-2020:1176)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:1176 advisory.

  - avahi: Multicast DNS responds to unicast queries outside
    of local network (CVE-2017-6519)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012411.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5088cbf9"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected avahi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6519");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-compat-howl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-compat-libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-compat-libdns_sd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-dnsconfd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-qt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-ui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-ui-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:avahi-ui-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-autoipd-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-compat-howl-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-compat-howl-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-compat-libdns_sd-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-compat-libdns_sd-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-dnsconfd-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-glib-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-glib-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-gobject-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-gobject-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-libs-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-qt3-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-qt3-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-qt4-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-qt4-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-tools-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-ui-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-ui-devel-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-ui-gtk3-0.6.31-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"avahi-ui-tools-0.6.31-20.el7")) flag++;


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
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi / avahi-autoipd / avahi-compat-howl / avahi-compat-howl-devel / etc");
}
