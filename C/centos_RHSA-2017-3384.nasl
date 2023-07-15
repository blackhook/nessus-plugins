#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3384 and 
# CentOS Errata and Security Advisory 2017:3384 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105061);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-15101");
  script_xref(name:"RHSA", value:"2017:3384");

  script_name(english:"CentOS 7 : liblouis (CESA-2017:3384)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for liblouis is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Liblouis is an open source braille translator and back-translator
named in honor of Louis Braille. It features support for computer and
literary braille, supports contracted and uncontracted translation for
many languages and has support for hyphenation. New languages can
easily be added through tables that support a rule or dictionary based
approach. Liblouis also supports math braille (Nemeth and Marburg).

Security Fix(es) :

* A missing fix for one stack-based buffer overflow in findTable() for
CVE-2014-8184 was discovered. An attacker could cause denial of
service or potentially allow arbitrary code execution.
(CVE-2017-15101)

Red Hat would like to thank Samuel Thibault for reporting this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-December/022684.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53f2837f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liblouis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15101");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:liblouis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:liblouis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:liblouis-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:liblouis-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:liblouis-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"liblouis-2.5.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"liblouis-devel-2.5.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"liblouis-doc-2.5.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"liblouis-python-2.5.2-12.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"liblouis-utils-2.5.2-12.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liblouis / liblouis-devel / liblouis-doc / liblouis-python / etc");
}
