#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3651. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130562);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/17");

  script_cve_id("CVE-2018-16838");
  script_xref(name:"RHSA", value:"2019:3651");

  script_name(english:"RHEL 8 : sssd (RHSA-2019:3651)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for sssd is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

The System Security Services Daemon (SSSD) service provides a set of
daemons to manage access to remote directories and authentication
mechanisms. It also provides the Name Service Switch (NSS) and the
Pluggable Authentication Modules (PAM) interfaces toward the system,
and a pluggable back-end system to connect to multiple different
account sources.

The following packages have been upgraded to a later upstream version:
sssd (2.2.0). (BZ#1687281)

Security Fix(es) :

* sssd: improper implementation of GPOs due to too restrictive
permissions (CVE-2018-16838)

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
    value:"https://access.redhat.com/errata/RHSA-2019:3651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-16838"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_autofs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_certmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_nss_idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_simpleifp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libipa_hbac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libsss_nss_idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sss-murmur-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-ad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-common-pac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-dbus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-kcm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-krb5-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-libwbclient-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-nfs-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-nfs-idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-polkit-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-proxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-winbind-idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2019:3651";
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
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libipa_hbac-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libipa_hbac-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libipa_hbac-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"libipa_hbac-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libipa_hbac-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libipa_hbac-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libipa_hbac-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_autofs-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_autofs-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"libsss_autofs-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsss_autofs-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_autofs-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_autofs-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsss_certmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_certmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_certmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"libsss_certmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsss_certmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_certmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_certmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsss_idmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_idmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_idmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"libsss_idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsss_idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsss_nss_idmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_nss_idmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_nss_idmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"libsss_nss_idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsss_nss_idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_nss_idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_nss_idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"libsss_nss_idmap-devel-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsss_nss_idmap-devel-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_nss_idmap-devel-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_nss_idmap-devel-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsss_simpleifp-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_simpleifp-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_simpleifp-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"libsss_simpleifp-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsss_simpleifp-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_simpleifp-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_simpleifp-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_sudo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_sudo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"libsss_sudo-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libsss_sudo-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libsss_sudo-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libsss_sudo-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-libipa_hbac-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libipa_hbac-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"python3-libipa_hbac-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-libipa_hbac-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-libipa_hbac-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libipa_hbac-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-libsss_nss_idmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libsss_nss_idmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"python3-libsss_nss_idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-libsss_nss_idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-libsss_nss_idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-libsss_nss_idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-sss-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-sss-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"python3-sss-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-sss-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-sss-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-sss-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-sss-murmur-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-sss-murmur-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"python3-sss-murmur-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"python3-sss-murmur-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"python3-sss-murmur-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"python3-sss-murmur-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"python3-sssdconfig-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-ad-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-ad-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-ad-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-ad-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-ad-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-ad-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-client-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-client-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-client-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-client-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-client-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-client-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-client-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-common-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-common-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-common-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-common-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-common-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-common-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-common-pac-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-common-pac-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-common-pac-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-common-pac-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-common-pac-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-common-pac-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-dbus-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-dbus-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-dbus-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-dbus-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-dbus-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-dbus-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-debugsource-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-debugsource-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-debugsource-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-debugsource-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-ipa-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-ipa-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-ipa-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-ipa-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-ipa-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-ipa-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-kcm-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-kcm-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-kcm-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-kcm-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-kcm-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-kcm-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-krb5-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-krb5-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-krb5-common-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-krb5-common-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-krb5-common-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-krb5-common-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-krb5-common-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-krb5-common-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-krb5-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-krb5-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-krb5-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-krb5-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-ldap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-ldap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-ldap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-ldap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-ldap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-ldap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-libwbclient-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-libwbclient-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-libwbclient-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-libwbclient-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-libwbclient-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-libwbclient-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-nfs-idmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-nfs-idmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-nfs-idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-nfs-idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-nfs-idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-nfs-idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-polkit-rules-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-proxy-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-proxy-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-proxy-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-proxy-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-proxy-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-proxy-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-tools-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-tools-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-tools-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-tools-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-tools-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-tools-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-winbind-idmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-winbind-idmap-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"sssd-winbind-idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"sssd-winbind-idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"sssd-winbind-idmap-debuginfo-2.2.0-19.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"sssd-winbind-idmap-debuginfo-2.2.0-19.el8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-debuginfo / libsss_autofs / etc");
  }
}
