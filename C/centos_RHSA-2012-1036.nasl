#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1036 and 
# CentOS Errata and Security Advisory 2012:1036 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59687);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-2143");
  script_bugtraq_id(53729);
  script_xref(name:"RHSA", value:"2012:1036");

  script_name(english:"CentOS 5 : postgresql (CESA-2012:1036)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # https://lists.centos.org/pipermail/centos-announce/2012-June/018698.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?baf9c00c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2143");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"postgresql-8.1.23-5.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-contrib-8.1.23-5.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-devel-8.1.23-5.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-docs-8.1.23-5.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-libs-8.1.23-5.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-pl-8.1.23-5.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-python-8.1.23-5.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-server-8.1.23-5.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-tcl-8.1.23-5.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-test-8.1.23-5.el5_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
