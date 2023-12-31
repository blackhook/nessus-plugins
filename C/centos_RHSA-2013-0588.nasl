#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0588 and 
# CentOS Errata and Security Advisory 2013:0588 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65032);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-1619");
  script_bugtraq_id(57736, 57778);
  script_xref(name:"RHSA", value:"2013:0588");

  script_name(english:"CentOS 5 / 6 : gnutls (CESA-2013:0588)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS).

It was discovered that GnuTLS leaked timing information when
decrypting TLS/SSL protocol encrypted records when CBC-mode cipher
suites were used. A remote attacker could possibly use this flaw to
retrieve plain text from the encrypted packets by using a TLS/SSL
server as a padding oracle. (CVE-2013-1619)

Users of GnuTLS are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. For the update
to take effect, all applications linked to the GnuTLS library must be
restarted, or the system rebooted."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019262.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff89aea6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019620.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57a43881"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-March/000817.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e91c52b7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1619");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"gnutls-1.4.1-10.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnutls-devel-1.4.1-10.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnutls-utils-1.4.1-10.el5_9.1")) flag++;

if (rpm_check(release:"CentOS-6", reference:"gnutls-2.8.5-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-devel-2.8.5-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-guile-2.8.5-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-utils-2.8.5-10.el6_4.1")) flag++;


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
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-devel / gnutls-guile / gnutls-utils");
}
