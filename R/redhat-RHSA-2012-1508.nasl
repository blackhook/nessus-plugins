#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1508. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78941);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-4316", "CVE-2012-0860", "CVE-2012-0861");
  script_bugtraq_id(56825);
  script_xref(name:"RHSA", value:"2012:1508");

  script_name(english:"RHEL 6 : rhev-3.1.0 vdsm (RHSA-2012:1508)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated vdsm packages are now available for Red Hat Enterprise Linux
6.3.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

VDSM is a management module that serves as a Red Hat Enterprise
Virtualization Manager agent on Red Hat Enterprise Virtualization
Hypervisor or Red Hat Enterprise Linux 6.3 hosts.

A flaw was found in the way Red Hat Enterprise Linux hosts were added
to the Red Hat Enterprise Virtualization environment. The Python
scripts needed to configure the host for Red Hat Enterprise
Virtualization were stored in the '/tmp/' directory and could be
pre-created by an attacker. A local, unprivileged user on the host to
be added to the Red Hat Enterprise Virtualization environment could
use this flaw to escalate their privileges. This update provides the
VDSM part of the fix. The RHSA-2012:1506 Red Hat Enterprise
Virtualization Manager update must also be installed to completely fix
this issue. (CVE-2012-0860)

A flaw was found in the way Red Hat Enterprise Linux and Red Hat
Enterprise Virtualization Hypervisor hosts were added to the Red Hat
Enterprise Virtualization environment. The Python scripts needed to
configure the host for Red Hat Enterprise Virtualization were
downloaded in an insecure way, that is, without properly validating
SSL certificates during HTTPS connections. An attacker on the local
network could use this flaw to conduct a man-in-the-middle attack,
potentially gaining root access to the host being added to the Red Hat
Enterprise Virtualization environment. This update provides the VDSM
part of the fix. The RHSA-2012:1506 Red Hat Enterprise Virtualization
Manager update must also be installed to completely fix this issue.
(CVE-2012-0861)

The CVE-2012-0860 and CVE-2012-0861 issues were discovered by Red Hat.

In addition to resolving the above security issues these updated VDSM
packages fix various bugs, and add various enhancements.

Documentation for these bug fixes and enhancements is available in the
Technical Notes :

https://access.redhat.com/knowledge/docs/en-US/
Red_Hat_Enterprise_Virtualization/3.1/html/Technical_Notes/index.html

All users who require VDSM are advised to install these updated
packages which resolve these security issues, fix these bugs, and add
these enhancements."
  );
  # https://access.redhat.com/knowledge/docs/en-US/
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-US/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:1508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-0861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-0860"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-vhostmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-reg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1508";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vdsm-4.9.6-44.0.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", reference:"vdsm-cli-4.9.6-44.0.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vdsm-debuginfo-4.9.6-44.0.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", reference:"vdsm-hook-vhostmd-4.9.6-44.0.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vdsm-python-4.9.6-44.0.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", reference:"vdsm-reg-4.9.6-44.0.el6_3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vdsm / vdsm-cli / vdsm-debuginfo / vdsm-hook-vhostmd / vdsm-python / etc");
  }
}
