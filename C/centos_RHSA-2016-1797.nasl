#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1797 and 
# CentOS Errata and Security Advisory 2016:1797 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93318);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-5404");
  script_xref(name:"RHSA", value:"2016:1797");

  script_name(english:"CentOS 6 / 7 : ipa (CESA-2016:1797)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ipa is now available for Red Hat Enterprise Linux 6 and
Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Identity Management (IdM) is a centralized authentication,
identity management, and authorization solution for both traditional
and cloud-based enterprise environments.

Security Fix(es) :

* An insufficient permission check issue was found in the way IPA
server treats certificate revocation requests. An attacker logged in
with the 'retrieve certificate' permission enabled could use this flaw
to revoke certificates, possibly triggering a denial of service
attack. (CVE-2016-5404)

This issue was discovered by Fraser Tweedale (Red Hat)."
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-September/022057.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86e5591e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-September/022060.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?051d2fee"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ipa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5404");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/06");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"ipa-admintools-3.0.0-50.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-client-3.0.0-50.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-python-3.0.0-50.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-server-3.0.0-50.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-server-selinux-3.0.0-50.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-server-trust-ad-3.0.0-50.el6.centos.2")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-admintools-4.2.0-15.0.1.el7.centos.19")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-client-4.2.0-15.0.1.el7.centos.19")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-python-4.2.0-15.0.1.el7.centos.19")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-4.2.0-15.0.1.el7.centos.19")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-dns-4.2.0-15.0.1.el7.centos.19")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.2.0-15.0.1.el7.centos.19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-python / ipa-server / etc");
}
