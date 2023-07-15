#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0675 and 
# CentOS Errata and Security Advisory 2007:0675 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25715);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-3377");
  script_bugtraq_id(24669);
  script_xref(name:"RHSA", value:"2007:0675");

  script_name(english:"CentOS 4 : perl-Net-DNS (CESA-2007:0675)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated perl-Net-DNS package that corrects a security issue is now
available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Net::DNS is a collection of Perl modules that act as a Domain Name
System (DNS) resolver.

A flaw was found in the way Net::DNS generated the ID field in a DNS
query. This predictable ID field could be used by a remote attacker to
return invalid DNS data. (CVE-2007-3377)

Users of Net::DNS should upgrade to this updated package, which
contains backported patches to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014026.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27c658fb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014038.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d6179c3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014039.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ddf13e9b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-net-dns package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Net-DNS");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/18");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"perl-Net-DNS-0.48-2.el4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-Net-DNS");
}
