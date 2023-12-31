#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1036. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59711);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2143");
  script_bugtraq_id(53729);
  script_xref(name:"RHSA", value:"2012:1036");

  script_name(english:"RHEL 5 : postgresql (RHSA-2012:1036)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix one security issue are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

A flaw was found in the way the crypt() password hashing function from
the optional PostgreSQL pgcrypto contrib module performed password
transformation when used with the DES algorithm. If the password
string to be hashed contained the 0x80 byte value, the remainder of
the string was ignored when calculating the hash, significantly
reducing the password strength. This made brute-force guessing more
efficient as the whole password was not required to gain access to
protected resources. (CVE-2012-2143)

Note: With this update, the rest of the string is properly included in
the DES hash; therefore, any previously stored password values that
are affected by this issue will no longer match. In such cases, it
will be necessary for those stored password hashes to be updated.

Upstream acknowledges Rubin Xu and Joseph Bonneau as the original
reporters of this issue.

All PostgreSQL users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. If the
postgresql service is running, it will be automatically restarted
after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:1036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-2143"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1036";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-contrib-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-contrib-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-contrib-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", reference:"postgresql-debuginfo-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", reference:"postgresql-devel-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-docs-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-docs-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-docs-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", reference:"postgresql-libs-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-pl-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-pl-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-pl-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-python-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-python-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-python-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-server-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-server-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-server-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-tcl-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-tcl-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-tcl-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-test-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-test-8.1.23-5.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-test-8.1.23-5.el5_8")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-debuginfo / etc");
  }
}
