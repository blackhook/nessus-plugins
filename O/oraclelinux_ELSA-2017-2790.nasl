#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2790 and 
# Oracle Linux Security Advisory ELSA-2017-2790 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103490);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-12150", "CVE-2017-12151", "CVE-2017-12163");
  script_xref(name:"RHSA", value:"2017:2790");

  script_name(english:"Oracle Linux 7 : samba (ELSA-2017-2790)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:2790 :

An update for samba is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) protocol and the related Common Internet File System (CIFS)
protocol, which allow PC-compatible machines to share files, printers,
and various information.

Security Fix(es) :

* It was found that samba did not enforce 'SMB signing' when certain
configuration options were enabled. A remote attacker could launch a
man-in-the-middle attack and retrieve information in plain-text.
(CVE-2017-12150)

* A flaw was found in the way samba client used encryption with the
max protocol set as SMB3. The connection could lose the requirement
for signing and encrypting to any DFS redirects, allowing an attacker
to read or alter the contents of the connection via a
man-in-the-middle attack. (CVE-2017-12151)

* An information leak flaw was found in the way SMB1 protocol was
implemented by Samba. A malicious client could use this flaw to dump
server memory contents to a file on the samba share or to a shared
printer, though the exact area of server memory cannot be controlled
by the attacker. (CVE-2017-12163)

Red Hat would like to thank the Samba project for reporting
CVE-2017-12150 and CVE-2017-12151 and Yihan Lian and Zhibin Hu (Qihoo
360 GearTeam), Stefan Metzmacher (SerNet), and Jeremy Allison (Google)
for reporting CVE-2017-12163. Upstream acknowledges Stefan Metzmacher
(SerNet) as the original reporter of CVE-2017-12150 and
CVE-2017-12151."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-September/007220.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ctdb-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ctdb-tests-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsmbclient-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsmbclient-devel-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libwbclient-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libwbclient-devel-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-client-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-client-libs-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-common-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-common-libs-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-common-tools-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-dc-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-dc-libs-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-devel-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-krb5-printing-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-libs-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-pidl-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-python-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-test-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-test-libs-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-winbind-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-winbind-clients-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-winbind-krb5-locator-4.6.2-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"samba-winbind-modules-4.6.2-11.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-tests / libsmbclient / libsmbclient-devel / libwbclient / etc");
}
