#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1854 and 
# CentOS Errata and Security Advisory 2017:1854 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102736);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3698", "CVE-2017-2640");
  script_xref(name:"RHSA", value:"2017:1854");
  script_xref(name:"IAVB", value:"2017-B-0029");

  script_name(english:"CentOS 7 : pidgin (CESA-2017:1854)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for pidgin is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

The following packages have been upgraded to a later upstream version:
pidgin (2.10.11). (BZ#1369526)

Security Fix(es) :

* A denial of service flaw was found in the way Pidgin's Mxit plug-in
handled emoticons. A malicious remote server or a man-in-the-middle
attacker could potentially use this flaw to crash Pidgin by sending a
specially crafted emoticon. (CVE-2014-3695)

* A denial of service flaw was found in the way Pidgin parsed
Groupwise server messages. A malicious remote server or a
man-in-the-middle attacker could potentially use this flaw to cause
Pidgin to consume an excessive amount of memory, possibly leading to a
crash, by sending a specially crafted message. (CVE-2014-3696)

* An information disclosure flaw was discovered in the way Pidgin
parsed XMPP messages. A malicious remote server or a man-in-the-middle
attacker could potentially use this flaw to disclose a portion of
memory belonging to the Pidgin process by sending a specially crafted
XMPP message. (CVE-2014-3698)

* An out-of-bounds write flaw was found in the way Pidgin processed
XML content. A malicious remote server could potentially use this flaw
to crash Pidgin or execute arbitrary code in the context of the pidgin
process. (CVE-2017-2640)

* It was found that Pidgin's SSL/TLS plug-ins had a flaw in the
certificate validation functionality. An attacker could use this flaw
to create a fake certificate, that Pidgin would trust, which could be
used to conduct man-in-the-middle attacks against Pidgin.
(CVE-2014-3694)

Red Hat would like to thank the Pidgin project for reporting these
issues. Upstream acknowledges Yves Younan (Cisco Talos) and Richard
Johnson (Cisco Talos) as the original reporters of CVE-2014-3695 and
CVE-2014-3696; Thijs Alkemade and Paul Aurich as the original
reporters of CVE-2014-3698; and Jacob Appelbaum and Moxie Marlinspike
as the original reporters of CVE-2014-3694.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.4 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004450.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47189eea"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2640");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"finch-2.10.11-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"finch-devel-2.10.11-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libpurple-2.10.11-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libpurple-devel-2.10.11-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libpurple-perl-2.10.11-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libpurple-tcl-2.10.11-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pidgin-2.10.11-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pidgin-devel-2.10.11-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pidgin-perl-2.10.11-5.el7")) flag++;


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
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
}
