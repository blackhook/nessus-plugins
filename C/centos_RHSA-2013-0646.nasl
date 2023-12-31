#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0646 and 
# CentOS Errata and Security Advisory 2013:0646 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65555);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274");
  script_bugtraq_id(57951, 57954);
  script_xref(name:"RHSA", value:"2013:0646");

  script_name(english:"CentOS 5 / 6 : pidgin (CESA-2013:0646)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pidgin packages that fix three security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

A stack-based buffer overflow flaw was found in the Pidgin MXit
protocol plug-in. A malicious server or a remote attacker could use
this flaw to crash Pidgin by sending a specially crafted HTTP request.
(CVE-2013-0272)

A buffer overflow flaw was found in the Pidgin Sametime protocol
plug-in. A malicious server or a remote attacker could use this flaw
to crash Pidgin by sending a specially crafted username.
(CVE-2013-0273)

A buffer overflow flaw was found in the way Pidgin processed certain
UPnP responses. A remote attacker could send a specially crafted UPnP
response that, when processed, would crash Pidgin. (CVE-2013-0274)

Red Hat would like to thank the Pidgin project for reporting the above
issues. Upstream acknowledges Daniel Atallah as the original reporter
of CVE-2013-0272.

All Pidgin users should upgrade to these updated packages, which
contain backported patches to resolve these issues. Pidgin must be
restarted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019647.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd80b17d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019648.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bafa02c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0272");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"finch-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"finch-devel-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-devel-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-perl-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-tcl-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-devel-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-perl-2.6.6-17.el5_9.1")) flag++;

if (rpm_check(release:"CentOS-6", reference:"finch-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"finch-devel-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpurple-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpurple-devel-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpurple-perl-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpurple-tcl-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pidgin-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pidgin-devel-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pidgin-docs-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pidgin-perl-2.7.9-10.el6_4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
}
