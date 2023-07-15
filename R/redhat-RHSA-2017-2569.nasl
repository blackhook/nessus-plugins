#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2569. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103038);
  script_version("3.11");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-7551");
  script_xref(name:"RHSA", value:"2017:2569");

  script_name(english:"RHEL 7 : 389-ds-base (RHSA-2017:2569)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for 389-ds-base is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

389 Directory Server is an LDAP version 3 (LDAPv3) compliant server.
The base packages include the Lightweight Directory Access Protocol
(LDAP) server and command-line utilities for server administration.

Security Fix(es) :

* A flaw was found in the way 389-ds-base handled authentication
attempts against locked accounts. A remote attacker could potentially
use this flaw to continue password brute-forcing attacks against LDAP
accounts, thereby bypassing the protection offered by the directory
server's password lockout policy. (CVE-2017-7551)

Bug Fix(es) :

* In a multi-replication environments, if operations in one back end
triggered updates in another back end, the Replica Update Vector (RUV)
of the back end was incorrect and replication failed. This fix enables
Directory Server to handle Change Sequence Number (CSN) pending lists
across multiple back ends. As a result, replication works correctly.
(BZ# 1476161)

* Due to a low default entry cache size value, the Directory Server
database had to resolve many deadlocks during resource-intensive
tasks. In certain situations, this could result in a 'DB PANIC' error
and the server no longer responded to requests. After the server was
restarted, Directory Server started with a delay to recover the
database. However, this recovery could fail, and the database could
corrupt. This patch increases the default entry cache size in the
nsslapd-cachememsize parameter to 200 MB. As a result, out-of-lock
situations or 'DB PANIC' errors no longer occur in the mentioned
scenario. (BZ#1476162)

* Previously, if replication was enabled and a changelog file existed,
performing a backup on this master server failed. This update sets the
internal options for correctly copying a file. As a result, creating a
backup now succeeds in the mentioned scenario. (BZ#1479755)

* In certain situations, if the server was previously abruptly shut
down, the /etc/dirsrv//dse.ldif configuration file became corrupted.
As a consequence, Directory Server failed to start. With this patch,
the server now calls the fsync() function before shutting down to
force the file system to write any changes to the disk. As a result,
the configuration no longer becomes corrupted, regardless how the
server gets stopped. (BZ# 1479757)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7551"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/08");
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
  rhsa = "RHSA-2017:2569";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"389-ds-base-1.3.6.1-19.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"389-ds-base-1.3.6.1-19.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"389-ds-base-debuginfo-1.3.6.1-19.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"389-ds-base-debuginfo-1.3.6.1-19.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"389-ds-base-devel-1.3.6.1-19.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.6.1-19.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"389-ds-base-libs-1.3.6.1-19.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.6.1-19.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"389-ds-base-snmp-1.3.6.1-19.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"389-ds-base-snmp-1.3.6.1-19.el7_4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-debuginfo / 389-ds-base-devel / etc");
  }
}
