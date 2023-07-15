#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3525. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130549);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2019-6470");
  script_xref(name:"RHSA", value:"2019:3525");
  script_xref(name:"IAVB", value:"2020-B-0036-S");

  script_name(english:"RHEL 8 : dhcp (RHSA-2019:3525)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for dhcp is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Dynamic Host Configuration Protocol (DHCP) is a protocol that
allows individual devices on an IP network to get their own network
configuration information, including an IP address, a subnet mask, and
a broadcast address. The dhcp packages provide a relay agent and ISC
DHCP service required to enable and administer DHCP on a network.

Security Fix(es) :

* dhcp: double-deletion of the released addresses in the dhcpv6 code
leading to crash and possible DoS (CVE-2019-6470)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 8.1 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?774148ae"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:3525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-6470"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-relay-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3525";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"dhcp-client-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dhcp-client-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"dhcp-client-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"dhcp-client-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dhcp-client-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"dhcp-common-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"dhcp-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"dhcp-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dhcp-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"dhcp-debugsource-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"dhcp-debugsource-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dhcp-debugsource-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"dhcp-libs-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"dhcp-libs-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dhcp-libs-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"dhcp-libs-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"dhcp-libs-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dhcp-libs-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"dhcp-relay-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dhcp-relay-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"dhcp-relay-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"dhcp-relay-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dhcp-relay-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"dhcp-server-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dhcp-server-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"dhcp-server-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"dhcp-server-debuginfo-4.3.6-34.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"dhcp-server-debuginfo-4.3.6-34.el8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp-client / dhcp-client-debuginfo / dhcp-common / dhcp-debuginfo / etc");
  }
}
