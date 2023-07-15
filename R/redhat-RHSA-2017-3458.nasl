#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3458. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105252);
  script_version("3.11");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2016-4978", "CVE-2016-4993", "CVE-2016-5406", "CVE-2016-6311", "CVE-2016-7046", "CVE-2016-7061", "CVE-2016-8627", "CVE-2016-8656", "CVE-2016-9589", "CVE-2017-12165", "CVE-2017-12167", "CVE-2017-2595", "CVE-2017-2666", "CVE-2017-2670", "CVE-2017-7525", "CVE-2017-7536", "CVE-2017-7559");
  script_xref(name:"RHSA", value:"2017:3458");

  script_name(english:"RHEL 6 / 7 : eap7-jboss-ec2-eap (RHSA-2017:3458)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for eap7-jboss-ec2-eap is now available for Red Hat JBoss
Enterprise Application Platform 7.1 for Red Hat Enterprise Linux 6 and
Red Hat JBoss Enterprise Application Platform 7.1 for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The eap7-jboss-ec2-eap packages provide scripts for Red Hat JBoss
Enterprise Application Platform running on the Amazon Web Services
(AWS) Elastic Compute Cloud (EC2).

With this update, the eap7-jboss-ec2-eap package has been updated to
ensure compatibility with Red Hat JBoss Enterprise Application
Platform 7.1.

Refer to the JBoss Enterprise Application Platform 7.1 Release Notes,
linked to in the References section, for information on the most
significant bug fixes and enhancements included in this release.

Security Fix(es) :

* A Denial of Service can be caused when a long request is sent to EAP
7. (CVE-2016-7046)

* The jboss init script unsafe file handling resulting in local
privilege escalation. (CVE-2016-8656)

* A deserialization vulnerability via readValue method of ObjectMapper
which allows arbitrary code execution. (CVE-2017-7525)

* JMSObjectMessage deserializes potentially malicious objects allowing
Remote Code Execution. (CVE-2016-4978)

* Undertow is vulnerable to the injection of arbitrary HTTP headers,
and also response splitting. (CVE-2016-4993)

* The domain controller will not propagate its administrative RBAC
configuration to some slaves leading to escalate their privileges.
(CVE-2016-5406)

* Internal IP address disclosed on redirect when request header Host
field is not set. (CVE-2016-6311)

* Potential EAP resource starvation DOS attack via GET requests for
server log files. (CVE-2016-8627)

* Inefficient Header Cache could cause denial of service.
(CVE-2016-9589)

* The log file viewer allows arbitrary file read to authenticated user
via path traversal. (CVE-2017-2595)

* HTTP Request smuggling vulnerability due to permitting invalid
characters in HTTP requests. (CVE-2017-2666)

* Websocket non clean close can cause IO thread to get stuck in a
loop. (CVE-2017-2670)

* Privilege escalation with security manager's reflective permissions
when granted to Hibernate Validator. (CVE-2017-7536)

* Potential http request smuggling as Undertow parses the http headers
with unusual whitespaces. (CVE-2017-7559)

* Properties based files of the management and the application realm
are world readable allowing access to users and roles information to
all the users logged in to the system. (CVE-2017-12167)

* RBAC configuration allows users with a Monitor role to view the
sensitive information. (CVE-2016-7061)

* Improper whitespace parsing leading to potential HTTP request
smuggling. (CVE-2017-12165)

Red Hat would like to thank Liao Xinxi (NSFOCUS) for reporting
CVE-2017-7525; Calum Hutton (NCC Group) and Mikhail Egorov (Odin) for
reporting CVE-2016-4993; Luca Bueti for reporting CVE-2016-6311;
Gabriel Lavoie (Halogen Software) for reporting CVE-2016-9589; and
Gregory Ramsperger and Ryan Moak for reporting CVE-2017-2670. The
CVE-2016-5406 issue was discovered by Tomaz Cerar (Red Hat); the
CVE-2016-8627 issue was discovered by Darran Lofthouse (Red Hat) and
Brian Stansberry (Red Hat); the CVE-2017-2666 issue was discovered by
Radim Hatlapatka (Red Hat); the CVE-2017-7536 issue was discovered by
Gunnar Morling (Red Hat); the CVE-2017-7559 and CVE-2017-12165 issues
were discovered by Stuart Douglas (Red Hat); and the CVE-2017-12167
issue was discovered by Brian Stansberry (Red Hat) and Jeremy Choi
(Red Hat). Upstream acknowledges WildFly as the original reporter of
CVE-2016-6311."
  );
  # https://access.redhat.com/documentation/en/
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:3458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12167"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected eap7-jboss-ec2-eap and / or
eap7-jboss-ec2-eap-samples packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ec2-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ec2-eap-samples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:3458";
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
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-ec2-eap-7.1.0-5.GA_redhat_5.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-ec2-eap-samples-7.1.0-5.GA_redhat_5.ep7.el6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-ec2-eap-7.1.0-5.GA_redhat_5.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-ec2-eap-samples-7.1.0-5.GA_redhat_5.ep7.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eap7-jboss-ec2-eap / eap7-jboss-ec2-eap-samples");
  }
}
