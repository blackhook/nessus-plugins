#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2022. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110794);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/01");

  script_cve_id("CVE-2018-10855");
  script_xref(name:"RHSA", value:"2018:2022");

  script_name(english:"RHEL 7 : ansible (RHSA-2018:2022)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for ansible is now available for Red Hat Ansible Engine 2.4
for RHEL 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Ansible is a simple model-driven configuration management, multi-node
deployment, and remote-task execution system. Ansible works over SSH
and does not require any software or daemons to be installed on remote
nodes. Extension modules can be written in any language and are
transferred to managed machines automatically.

The following packages have been upgraded to a newer upstream version:
ansible (2.4.5)

Security fix(es) :

* ansible: Ansible through version 2.5 does not properly honour the
no_log option with failed task iterations. When a list of secret items
is supplied to a task and a task iteration fails, secrets can be
disclosed in logs despite the no_log option being enabled.
(CVE-2018-10855)

Red Hat would like to thank Tobias Henkel (BMW Car IT GmbH) for
reporting these issues.

Bug Fix(es) :

* Fixed win_copy to preserve the global Ansible local tmp path instead
of deleting it when dealing with multiple files
(https://github.com/ansible/ansible/pull/37964)

* Fixed Windows setup.ps1 for slow performance in large domain
environments (https://github.com/ansible/ansible/pull/38646)

* Fixed eos_logging idempotency issue when trying to set both logging
destination & facility (https://github.com/ansible/ansible/pull/40604)

* Fixed ios_logging idempotency issue when trying to set both logging
destination & facility (https://github.com/ansible/ansible/pull/41076)

See https://github.com/ansible/ansible/blob/v2.4.5.0-1/CHANGELOG.md
for details on this release."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-10855"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected ansible and / or ansible-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2018:2022";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"ansible-2.4"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Red Hat Ansible 2.4");

  if (rpm_check(release:"RHEL7", reference:"ansible-2.4.5.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ansible-doc-2.4.5.0-1.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ansible / ansible-doc");
  }
}
