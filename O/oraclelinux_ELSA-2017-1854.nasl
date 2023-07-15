#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:1854 and 
# Oracle Linux Security Advisory ELSA-2017-1854 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102283);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3698", "CVE-2017-2640");
  script_xref(name:"RHSA", value:"2017:1854");
  script_xref(name:"IAVB", value:"2017-B-0029");

  script_name(english:"Oracle Linux 7 : pidgin (ELSA-2017-1854)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:1854 :

An update for pidgin is now available for Red Hat Enterprise Linux 7.

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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-August/007075.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"finch-2.10.11-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"finch-devel-2.10.11-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libpurple-2.10.11-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libpurple-devel-2.10.11-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libpurple-perl-2.10.11-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libpurple-tcl-2.10.11-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pidgin-2.10.11-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pidgin-devel-2.10.11-5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pidgin-perl-2.10.11-5.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
}
