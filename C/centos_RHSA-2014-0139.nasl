#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0139 and 
# CentOS Errata and Security Advisory 2014:0139 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72352);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");
  script_bugtraq_id(65188, 65192, 65195, 65243, 65492);
  script_xref(name:"RHSA", value:"2014:0139");

  script_name(english:"CentOS 5 / 6 : pidgin (CESA-2014:0139)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pidgin packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

A heap-based buffer overflow flaw was found in the way Pidgin
processed certain HTTP responses. A malicious server could send a
specially crafted HTTP response, causing Pidgin to crash or
potentially execute arbitrary code with the permissions of the user
running Pidgin. (CVE-2013-6485)

Multiple heap-based buffer overflow flaws were found in several
protocol plug-ins in Pidgin (Gadu-Gadu, MXit, SIMPLE). A malicious
server could send a specially crafted message, causing Pidgin to crash
or potentially execute arbitrary code with the permissions of the user
running Pidgin. (CVE-2013-6487, CVE-2013-6489, CVE-2013-6490)

Multiple denial of service flaws were found in several protocol
plug-ins in Pidgin (Yahoo!, XMPP, MSN, stun, IRC). A remote attacker
could use these flaws to crash Pidgin by sending a specially crafted
message. (CVE-2012-6152, CVE-2013-6477, CVE-2013-6481, CVE-2013-6482,
CVE-2013-6484, CVE-2014-0020)

It was found that the Pidgin XMPP protocol plug-in did not verify the
origin of 'iq' replies. A remote attacker could use this flaw to spoof
an 'iq' reply, which could lead to injection of fake data or cause
Pidgin to crash via a NULL pointer dereference. (CVE-2013-6483)

A flaw was found in the way Pidgin parsed certain HTTP response
headers. A remote attacker could use this flaw to crash Pidgin via a
specially crafted HTTP response header. (CVE-2013-6479)

It was found that Pidgin crashed when a mouse pointer was hovered over
a long URL. A remote attacker could use this flaw to crash Pidgin by
sending a message containing a long URL string. (CVE-2013-6478)

Red Hat would like to thank the Pidgin project for reporting these
issues. Upstream acknowledges Thijs Alkemade, Robert Vehse, Jaime
Breva Ribes, Jacob Appelbaum of the Tor Project, Daniel Atallah,
Fabian Yamaguchi and Christian Wressnegger of the University of
Goettingen, Matt Jones of Volvent, and Yves Younan, Ryan Pentney, and
Pawel Janic of Sourcefire VRT as the original reporters of these
issues.

All pidgin users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. Pidgin must
be restarted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-February/020141.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ef12403"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-February/020142.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a6dc642"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-6490");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"finch-2.6.6-32.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"finch-devel-2.6.6-32.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-2.6.6-32.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-devel-2.6.6-32.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-perl-2.6.6-32.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpurple-tcl-2.6.6-32.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-2.6.6-32.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-devel-2.6.6-32.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pidgin-perl-2.6.6-32.el5")) flag++;

if (rpm_check(release:"CentOS-6", reference:"finch-2.7.9-27.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"finch-devel-2.7.9-27.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpurple-2.7.9-27.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpurple-devel-2.7.9-27.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpurple-perl-2.7.9-27.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpurple-tcl-2.7.9-27.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pidgin-2.7.9-27.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pidgin-devel-2.7.9-27.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pidgin-docs-2.7.9-27.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pidgin-perl-2.7.9-27.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
}
