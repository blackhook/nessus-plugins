#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2577 and 
# CentOS Errata and Security Advisory 2016:2577 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95324);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-5160", "CVE-2015-5313", "CVE-2016-5008");
  script_xref(name:"RHSA", value:"2016:2577");

  script_name(english:"CentOS 7 : libvirt (CESA-2016:2577)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libvirt is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libvirt library contains a C API for managing and interacting with
the virtualization capabilities of Linux and other operating systems.
In addition, libvirt provides tools for remote management of
virtualized systems.

The following packages have been upgraded to a newer upstream version:
libvirt (2.0.0). (BZ#830971, BZ#1286679)

Security Fix(es) :

* It was found that the libvirt daemon, when using RBD (RADOS Block
Device), leaked private credentials to the process list. A local
attacker could use this flaw to perform certain privileged operations
within the cluster. (CVE-2015-5160)

* A path-traversal flaw was found in the way the libvirt daemon
handled filesystem names for storage volumes. A libvirt user with
privileges to create storage volumes and without privileges to create
and modify domains could possibly use this flaw to escalate their
privileges. (CVE-2015-5313)

* It was found that setting a VNC password to an empty string in
libvirt did not disable all access to the VNC server as documented,
instead it allowed access with no authentication required. An attacker
could use this flaw to access a VNC server with an empty VNC password
without any authentication. (CVE-2016-5008)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-November/003620.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e54d212d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5008");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-client-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-config-network-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-kvm-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-lxc-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-devel-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-docs-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-lock-sanlock-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-login-shell-2.0.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-nss-2.0.0-10.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-daemon / etc");
}
