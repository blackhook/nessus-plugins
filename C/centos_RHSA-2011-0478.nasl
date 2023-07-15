#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0478 and 
# CentOS Errata and Security Advisory 2011:0478 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53643);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-1486");
  script_bugtraq_id(47148);
  script_xref(name:"RHSA", value:"2011:0478");

  script_name(english:"CentOS 5 : libvirt / libvirt.test (CESA-2011:0478)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remotely managing virtualized
systems.

A flaw was found in the way libvirtd handled error reporting for
concurrent connections. A remote attacker able to establish read-only
connections to libvirtd on a server could use this flaw to crash
libvirtd. (CVE-2011-1486)

All libvirt users are advised to upgrade to these updated packages,
which contain backported patches to resolve this issue. After
installing the updated packages, libvirtd must be restarted ('service
libvirtd restart') for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-May/017478.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d77fa98"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-May/017479.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef207a88"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-May/017480.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03828a46"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-May/017481.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b4d7101"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt and / or libvirt.test packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"libvirt-0.8.2-15.el5_6.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvirt-devel-0.8.2-15.el5_6.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvirt-python-0.8.2-15.el5_6.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-devel / libvirt-python");
}
