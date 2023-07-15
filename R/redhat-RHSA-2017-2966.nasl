#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2966. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104005);
  script_version("3.9");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-7550");
  script_xref(name:"RHSA", value:"2017:2966");

  script_name(english:"RHEL 7 : ansible (RHSA-2017:2966)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ansible is now available for Red Hat Enterprise Linux 7
Extras.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Ansible is a simple model-driven configuration management, multi-node
deployment, and remote-task execution system. Ansible works over SSH
and does not require any software or daemons to be installed on remote
nodes. Extension modules can be written in any language and are
transferred to managed machines automatically.

The ansible packages have been upgraded to upstream version 2.4.0,
which provides a number of bug fixes and enhancements over the
previous version. For more information, please see the Ansible 2.4
Porting Guide linked in the References section. (BZ#1492477)

Security Fix(es) :

* A flaw was found in the way Ansible passed certain parameters to the
jenkins_plugin module. A remote attacker could use this flaw to expose
sensitive information from a remote host's logs. This flaw was fixed
by not allowing passwords to be specified in the 'params' argument,
and noting this in the module documentation. (CVE-2017-7550)

Red Hat would like to thank Stefano Mazzucco (Kirontech) for reporting
this issue.

Bug Fix(es) :

* A bug in the SELinux module, which caused a corruption of the
SELinux configuration file, has been fixed.

* Previously, some of the functionality of Ansible (the json_query
filter) was unavailable, because the dependency on the
python2-jmespath package was missing. Now, the missing dependency has
been added. (BZ#1484910)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.ansible.com/ansible/2.4/porting_guide_2.4.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7550"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ansible and / or ansible-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");
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
  rhsa = "RHSA-2017:2966";
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
  if (rpm_check(release:"RHEL7", reference:"ansible-2.4.0.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ansible-doc-2.4.0.0-5.el7")) flag++;

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
