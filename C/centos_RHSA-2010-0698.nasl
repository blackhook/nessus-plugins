#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0698 and 
# CentOS Errata and Security Advisory 2010:0698 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49262);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-3069");
  script_bugtraq_id(43212);
  script_xref(name:"RHSA", value:"2010:0698");

  script_name(english:"CentOS 5 : samba3x (CESA-2010:0698)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba3x packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Samba is a suite of programs used by machines to share files,
printers, and other information.

A missing array boundary checking flaw was found in the way Samba
parsed the binary representation of Windows security identifiers
(SIDs). A malicious client could send a specially crafted SMB request
to the Samba server, resulting in arbitrary code execution with the
privileges of the Samba server (smbd). (CVE-2010-3069)

Users of Samba are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing
this update, the smb service will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/017004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb1e8813"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/017005.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3d2a5e6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba3x packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tdb-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"libtalloc-1.2.0-52.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtalloc-devel-1.2.0-52.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtdb-1.1.2-52.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtdb-devel-1.1.2-52.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-client-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-common-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-doc-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-domainjoin-gui-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-swat-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-winbind-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-winbind-devel-3.3.8-0.52.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tdb-tools-1.1.2-52.el5_5.2")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtalloc / libtalloc-devel / libtdb / libtdb-devel / samba3x / etc");
}
