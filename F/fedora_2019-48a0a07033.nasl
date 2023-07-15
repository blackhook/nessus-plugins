#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-48a0a07033.
#

include("compat.inc");

if (description)
{
  script_id(130783);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/12");

  script_cve_id("CVE-2019-2911", "CVE-2019-2914", "CVE-2019-2938", "CVE-2019-2946", "CVE-2019-2957", "CVE-2019-2960", "CVE-2019-2963", "CVE-2019-2966", "CVE-2019-2967", "CVE-2019-2968", "CVE-2019-2974", "CVE-2019-2982", "CVE-2019-2991", "CVE-2019-2993", "CVE-2019-2997", "CVE-2019-2998", "CVE-2019-3004", "CVE-2019-3009", "CVE-2019-3011", "CVE-2019-3018");
  script_xref(name:"FEDORA", value:"2019-48a0a07033");

  script_name(english:"Fedora 30 : community-mysql (2019-48a0a07033)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**MySQL 8.0.18**

Release notes :

https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-18.html

CVEs fixed :

CVE-2019-2911 CVE-2019-2914 CVE-2019-2938 CVE-2019-2946 CVE-2019-2957
CVE-2019-2960 CVE-2019-2963 CVE-2019-2966 CVE-2019-2967 CVE-2019-2968
CVE-2019-2974 CVE-2019-2982 CVE-2019-2991 CVE-2019-2993 CVE-2019-2997
CVE-2019-2998 CVE-2019-3004 CVE-2019-3009 CVE-2019-3011 CVE-2019-3018
https://bugzilla.redhat.com/show_bug.cgi?id=1768175
https://www.oracle.com/security-alerts/cpuoct2019.html

Maintainer notes :

linking with GOLD disabled on armv7hl, because of
https://bugs.mysql.com/bug.php?id=96698

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-48a0a07033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.mysql.com/bug.php?id=96698"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected community-mysql package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2991");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:community-mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"community-mysql-8.0.18-1.fc30")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "community-mysql");
}
