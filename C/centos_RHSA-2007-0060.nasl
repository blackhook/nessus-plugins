#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0060 and 
# CentOS Errata and Security Advisory 2007:0060 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24358);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0452");
  script_bugtraq_id(22395);
  script_xref(name:"RHSA", value:"2007:0060");

  script_name(english:"CentOS 3 / 4 : samba (CESA-2007:0060)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba packages that fix a denial of service vulnerability are
now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Samba provides file and printer sharing services to SMB/CIFS clients.

A denial of service flaw was found in Samba's smbd daemon process. An
authenticated user could send a specially crafted request which would
cause a smbd child process to enter an infinite loop condition. By
opening multiple CIFS sessions, an attacker could exhaust system
resources. (CVE-2007-0452)

Users of Samba should update to these packages, which contain a
backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013526.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32d0d119"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013527.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66dde7c8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013532.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?774c5f24"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013533.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1be018aa"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013538.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de2939cd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013539.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?918917eb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"samba-3.0.9-1.3E.12")) flag++;
if (rpm_check(release:"CentOS-3", reference:"samba-client-3.0.9-1.3E.12")) flag++;
if (rpm_check(release:"CentOS-3", reference:"samba-common-3.0.9-1.3E.12")) flag++;
if (rpm_check(release:"CentOS-3", reference:"samba-swat-3.0.9-1.3E.12")) flag++;

if (rpm_check(release:"CentOS-4", reference:"samba-3.0.10-1.4E.11")) flag++;
if (rpm_check(release:"CentOS-4", reference:"samba-client-3.0.10-1.4E.11")) flag++;
if (rpm_check(release:"CentOS-4", reference:"samba-common-3.0.10-1.4E.11")) flag++;
if (rpm_check(release:"CentOS-4", reference:"samba-swat-3.0.10-1.4E.11")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba / samba-client / samba-common / samba-swat");
}
