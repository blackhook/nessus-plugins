#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:0009 and 
# Oracle Linux Security Advisory ELSA-2016-0009 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87796);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-3223", "CVE-2015-5330");
  script_xref(name:"RHSA", value:"2016:0009");

  script_name(english:"Oracle Linux 6 / 7 : libldb (ELSA-2016-0009)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:0009 :

Updated libldb packages that fix two security issues are now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libldb packages provide an extensible library that implements an
LDAP-like API to access remote LDAP servers, or use local TDB
databases.

A denial of service flaw was found in the ldb_wildcard_compare()
function of libldb. A remote attacker could send a specially crafted
packet that, when processed by an application using libldb (for
example the AD LDAP server in Samba), would cause that application to
consume an excessive amount of memory and crash. (CVE-2015-3223)

A memory-read flaw was found in the way the libldb library processed
LDB DN records with a null byte. An authenticated, remote attacker
could use this flaw to read heap-memory pages from the server.
(CVE-2015-5330)

Red Hat would like to thank the Samba project for reporting these
issues. Upstream acknowledges Thilo Uttendorfer as the original
reporter of CVE-2015-3223, and Douglas Bagnall as the original
reporter of CVE-2015-5330.

All libldb users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-January/005663.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-January/005668.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libldb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pyldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pyldb-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"ldb-tools-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"EL6", reference:"libldb-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"EL6", reference:"libldb-devel-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"EL6", reference:"pyldb-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"EL6", reference:"pyldb-devel-1.1.13-3.el6_7.1")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ldb-tools-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libldb-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libldb-devel-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pyldb-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pyldb-devel-1.1.20-1.el7_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldb-tools / libldb / libldb-devel / pyldb / pyldb-devel");
}
