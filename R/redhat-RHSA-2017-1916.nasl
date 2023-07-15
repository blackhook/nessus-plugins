#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1916. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102149);
  script_version("3.11");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2014-9761", "CVE-2015-8776", "CVE-2015-8777", "CVE-2015-8778", "CVE-2015-8779");
  script_xref(name:"RHSA", value:"2017:1916");

  script_name(english:"RHEL 7 : glibc (RHSA-2017:1916)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for glibc is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
name service cache daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

Security Fix(es) :

* A stack overflow vulnerability was found in nan* functions that
could cause applications, which process long strings with the nan
function, to crash or, potentially, execute arbitrary code.
(CVE-2014-9761)

* It was found that out-of-range time values passed to the strftime()
function could result in an out-of-bounds memory access. This could
lead to application crash or, potentially, information disclosure.
(CVE-2015-8776)

* An integer overflow vulnerability was found in hcreate() and
hcreate_r() functions which could result in an out-of-bounds memory
access. This could lead to application crash or, potentially,
arbitrary code execution. (CVE-2015-8778)

* A stack based buffer overflow vulnerability was found in the
catopen() function. An excessively long string passed to the function
could cause it to crash or, potentially, execute arbitrary code.
(CVE-2015-8779)

* It was found that the dynamic loader did not sanitize the
LD_POINTER_GUARD environment variable. An attacker could use this flaw
to bypass the pointer guarding protection on set-user-ID or
set-group-ID programs to execute arbitrary code with the permissions
of the user running the application. (CVE-2015-8777)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.4 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3395ff0b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-9761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8779"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1916";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", reference:"glibc-2.17-196.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-common-2.17-196.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-common-2.17-196.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-debuginfo-2.17-196.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-debuginfo-common-2.17-196.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-devel-2.17-196.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-headers-2.17-196.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-headers-2.17-196.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"glibc-static-2.17-196.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glibc-utils-2.17-196.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glibc-utils-2.17-196.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nscd-2.17-196.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nscd-2.17-196.el7")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
  }
}
