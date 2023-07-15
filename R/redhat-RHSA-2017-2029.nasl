#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2029. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102112);
  script_version("3.11");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2016-10009", "CVE-2016-10011", "CVE-2016-10012", "CVE-2016-10708", "CVE-2016-6210", "CVE-2016-6515");
  script_xref(name:"RHSA", value:"2017:2029");

  script_name(english:"RHEL 7 : openssh (RHSA-2017:2029)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for openssh is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenSSH is an SSH protocol implementation supported by a number of
Linux, UNIX, and similar operating systems. It includes the core files
necessary for both the OpenSSH client and server.

The following packages have been upgraded to a later upstream version:
openssh (7.4p1). (BZ#1341754)

Security Fix(es) :

* A covert timing channel flaw was found in the way OpenSSH handled
authentication of non-existent users. A remote unauthenticated
attacker could possibly use this flaw to determine valid user names by
measuring the timing of server responses. (CVE-2016-6210)

* It was found that OpenSSH did not limit password lengths for
password authentication. A remote unauthenticated attacker could use
this flaw to temporarily trigger high CPU consumption in sshd by
sending long passwords. (CVE-2016-6515)

* It was found that ssh-agent could load PKCS#11 modules from
arbitrary paths. An attacker having control of the forwarded
agent-socket on the server, and the ability to write to the filesystem
of the client host, could use this flaw to execute arbitrary code with
the privileges of the user running ssh-agent. (CVE-2016-10009)

* It was found that the host private key material could possibly leak
to the privilege-separated child processes via re-allocated memory. An
attacker able to compromise the privilege-separated process could
therefore obtain the leaked key information. (CVE-2016-10011)

* It was found that the boundary checks in the code implementing
support for pre-authentication compression could have been optimized
out by certain compilers. An attacker able to compromise the
privilege-separated process could possibly use this flaw for further
attacks against the privileged monitor process. (CVE-2016-10012)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.4 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3395ff0b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-10009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-10011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-10012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-10708"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-server-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/02");
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
  rhsa = "RHSA-2017:2029";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssh-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssh-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssh-askpass-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssh-askpass-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssh-cavs-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssh-cavs-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssh-clients-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssh-clients-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssh-debuginfo-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssh-keycat-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssh-keycat-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssh-ldap-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssh-ldap-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssh-server-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssh-server-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssh-server-sysvinit-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssh-server-sysvinit-7.4p1-11.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"pam_ssh_agent_auth-0.10.3-1.11.el7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-cavs / openssh-clients / etc");
  }
}
