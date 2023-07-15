#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0423. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119349);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-0188");
  script_bugtraq_id(67037);
  script_xref(name:"RHSA", value:"2014:0423");

  script_name(english:"RHEL 6 : openshift-origin-broker (RHSA-2014:0423)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated openshift-origin-broker and
rubygem-openshift-origin-auth-remote-user packages that fix one
security issue are now available for Red Hat OpenShift Enterprise
2.0.5.

The Red Hat Security Response Team has rated this update as having
Critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The openshift-origin-broker package provides the OpenShift Broker
service that manages all user logins, DNS name resolution, application
states, and general orchestration of the applications.

The rubygem-openshift-origin-auth-remote-user package provides the
remote user authentication plug-in.

A flaw was found in the way openshift-origin-broker handled
authentication requests via the remote user authentication plug-in. A
remote attacker able to submit a request to openshift-origin-broker
could set the X-Remote-User header, and send the request to a
passthrough trigger, resulting in a bypass of the authentication
checks to gain access to any OpenShift user account on the system.
(CVE-2014-0188)

All users of Red Hat OpenShift Enterprise 2.0.5 are advised to upgrade
to these updated packages, which contain a backported patch to correct
this issue. After installing the updated packages, restart the httpd
daemon for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:0423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0188"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected openshift-origin-broker and / or
rubygem-openshift-origin-auth-remote-user packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-auth-remote-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2014:0423";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-broker-1.15.3.5-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-auth-remote-user-1.17.4-1.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openshift-origin-broker / rubygem-openshift-origin-auth-remote-user");
  }
}
