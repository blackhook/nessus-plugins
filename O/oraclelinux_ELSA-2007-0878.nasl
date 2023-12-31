#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0878 and 
# Oracle Linux Security Advisory ELSA-2007-0878 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67567);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-1721");
  script_xref(name:"RHSA", value:"2007:0878");

  script_name(english:"Oracle Linux 3 : cyrus-sasl (ELSA-2007-0878)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0878 :

Updated cyrus-sasl packages that correct a security issue are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The cyrus-sasl package contains the Cyrus implementation of SASL. SASL
is the Simple Authentication and Security Layer, a method for adding
authentication support to connection-based protocols.

A bug was found in cyrus-sasl's DIGEST-MD5 authentication mechanism.
As part of the DIGEST-MD5 authentication exchange, the client is
expected to send a specific set of information to the server. If one
of these items (the 'realm') was not sent or was malformed, it was
possible for a remote unauthenticated attacker to cause a denial of
service (segmentation fault) on the server. (CVE-2006-1721)

Users of cyrus-sasl should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-September/000313.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-sasl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl-md5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl-plain");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cyrus-sasl-2.1.15-15")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cyrus-sasl-2.1.15-15")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cyrus-sasl-devel-2.1.15-15")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cyrus-sasl-devel-2.1.15-15")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cyrus-sasl-gssapi-2.1.15-15")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cyrus-sasl-gssapi-2.1.15-15")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cyrus-sasl-md5-2.1.15-15")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cyrus-sasl-md5-2.1.15-15")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cyrus-sasl-plain-2.1.15-15")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cyrus-sasl-plain-2.1.15-15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-sasl / cyrus-sasl-devel / cyrus-sasl-gssapi / cyrus-sasl-md5 / etc");
}
