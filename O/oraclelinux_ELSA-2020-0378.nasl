#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0378 and 
# Oracle Linux Security Advisory ELSA-2020-0378 respectively.
#

include("compat.inc");

if (description)
{
  script_id(133515);
  script_version("1.2");
  script_cvs_date("Date: 2020/02/10");

  script_cve_id("CVE-2019-10195", "CVE-2019-14867");
  script_xref(name:"RHSA", value:"2020:0378");

  script_name(english:"Oracle Linux 7 : ipa (ELSA-2020-0378)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2020:0378 :

An update for ipa is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Identity Management (IdM) is a centralized authentication,
identity management, and authorization solution for both traditional
and cloud-based enterprise environments.

Security Fix(es) :

* ipa: Denial of service in IPA server due to wrong use of ber_scanf()
(CVE-2019-14867)

* ipa: Batch API logging user passwords to /var/log/httpd/error_log
(CVE-2019-10195)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* Issue with adding multiple RHEL 7 IPA replica to RHEL 6 IPA master
(BZ# 1770728)

* User incorrectly added to negative cache when backend is
reconnecting to IPA service / timed out: error code 32 'No such
object' (BZ#1773953)

* After upgrade AD Trust Agents were removed from LDAP (BZ#1781153)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2020-February/009594.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ipa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-client-4.6.5-11.0.1.el7_7.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-client-common-4.6.5-11.0.1.el7_7.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-common-4.6.5-11.0.1.el7_7.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-python-compat-4.6.5-11.0.1.el7_7.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-server-4.6.5-11.0.1.el7_7.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-server-common-4.6.5-11.0.1.el7_7.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-server-dns-4.6.5-11.0.1.el7_7.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.6.5-11.0.1.el7_7.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python2-ipaclient-4.6.5-11.0.1.el7_7.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python2-ipalib-4.6.5-11.0.1.el7_7.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python2-ipaserver-4.6.5-11.0.1.el7_7.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-client / ipa-client-common / ipa-common / ipa-python-compat / etc");
}
