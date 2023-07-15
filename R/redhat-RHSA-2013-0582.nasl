#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0582. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119432);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2660", "CVE-2012-2661", "CVE-2012-2694", "CVE-2012-2695", "CVE-2012-3424", "CVE-2012-3463", "CVE-2012-3464", "CVE-2012-3465", "CVE-2012-4464", "CVE-2012-4466", "CVE-2012-4522", "CVE-2012-5371", "CVE-2013-0155", "CVE-2013-0162", "CVE-2013-0276");
  script_bugtraq_id(53753, 53754, 53970, 53976, 54704, 54957, 54958, 54959, 55757, 56115, 56484, 57192, 58110);
  script_xref(name:"RHSA", value:"2013:0582");

  script_name(english:"RHEL 6 : openshift (RHSA-2013:0582)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Red Hat OpenShift Enterprise 1.1.1 is now available.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenShift Enterprise is a cloud computing Platform-as-a-Service (PaaS)
solution from Red Hat, and is designed for on-premise or private cloud
deployments.

Installing the updated packages and restarting the OpenShift services
are the only requirements for this update. However, if you are
updating your system to Red Hat Enterprise Linux 6.4 while applying
OpenShift Enterprise 1.1.1 updates, it is recommended that you restart
your system.

For further information about this release, refer to the OpenShift
Enterprise 1.1.1 Technical Notes, available shortly from
https://access.redhat.com/knowledge/docs/

This update also fixes the following security issues :

Multiple cross-site scripting (XSS) flaws were found in
rubygem-actionpack. A remote attacker could use these flaws to conduct
XSS attacks against users of an application using rubygem-actionpack.
(CVE-2012-3463, CVE-2012-3464, CVE-2012-3465)

It was found that certain methods did not sanitize file names before
passing them to lower layer routines in Ruby. If a Ruby application
created files with names based on untrusted input, it could result in
the creation of files with different names than expected.
(CVE-2012-4522)

A denial of service flaw was found in the implementation of
associative arrays (hashes) in Ruby. An attacker able to supply a
large number of inputs to a Ruby application (such as HTTP POST
request parameters sent to a web application) that are used as keys
when inserting data into an array could trigger multiple hash function
collisions, making array operations take an excessive amount of CPU
time. To mitigate this issue, a new, more collision resistant
algorithm has been used to reduce the chance of an attacker
successfully causing intentional collisions. (CVE-2012-5371)

Input validation vulnerabilities were discovered in
rubygem-activerecord. A remote attacker could possibly use these flaws
to perform a SQL injection attack against an application using
rubygem-activerecord. (CVE-2012-2661, CVE-2012-2695, CVE-2013-0155)

Input validation vulnerabilities were discovered in
rubygem-actionpack. A remote attacker could possibly use these flaws
to perform a SQL injection attack against an application using
rubygem-actionpack and rubygem-activerecord. (CVE-2012-2660,
CVE-2012-2694)

A flaw was found in the HTTP digest authentication implementation in
rubygem-actionpack. A remote attacker could use this flaw to cause a
denial of service of an application using rubygem-actionpack and
digest authentication. (CVE-2012-3424)

A flaw was found in the handling of strings in Ruby safe level 4. A
remote attacker can use Exception#to_s to destructively modify an
untainted string so that it is tainted, the string can then be
arbitrarily modified. (CVE-2012-4466)

A flaw was found in the method for translating an exception message
into a string in the Ruby Exception class. A remote attacker could use
this flaw to bypass safe level 4 restrictions, allowing untrusted
(tainted) code to modify arbitrary, trusted (untainted) strings, which
safe level 4 restrictions would otherwise prevent. (CVE-2012-4464)

It was found that ruby_parser from rubygem-ruby_parser created a
temporary file in an insecure way. A local attacker could use this
flaw to perform a symbolic link attack, overwriting arbitrary files
accessible to the application using ruby_parser. (CVE-2013-0162)

The CVE-2013-0162 issue was discovered by Michael Scherer of the Red
Hat Regional IT team.

Users are advised to upgrade to Red Hat OpenShift Enterprise 1.1.1."
  );
  # https://access.redhat.com/knowledge/docs/
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-2660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-2661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-2694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-2695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0276"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:graphviz-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:graphviz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:graphviz-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:graphviz-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:graphviz-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-cron-1.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-diy-0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-haproxy-1.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbosseap-6.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbossews-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jenkins-1.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jenkins-client-1.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-mysql-5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-perl-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-php-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-postgresql-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-ruby-1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-ruby-1.9-scl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-msg-node-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-actionpack-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activemodel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activerecord-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-railties");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-railties-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby_parser-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activemodel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-auth-remote-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-console-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ruby_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ruby_parser-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/06");
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
  rhsa = "RHSA-2013:0582";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"graphviz-2.26.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"graphviz-debuginfo-2.26.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"graphviz-devel-2.26.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"graphviz-doc-2.26.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"graphviz-gd-2.26.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"graphviz-ruby-2.26.0-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-console-0.0.16-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-broker-1.0.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-broker-util-1.0.15-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-cron-1.4-1.0.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-diy-0.1-1.0.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-haproxy-1.4-1.0.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-jbosseap-6.0-1.0.4-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-jbossews-1.0-1.0.13-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-jenkins-1.4-1.0.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-jenkins-client-1.4-1.0.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-mysql-5.1-1.0.5-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-perl-5.10-1.0.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-php-5.3-1.0.5-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-postgresql-8.4-1.0.3-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-ruby-1.8-1.0.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-cartridge-ruby-1.9-scl-1.0.8-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openshift-origin-msg-node-mcollective-1.0.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-bcmath-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-debuginfo-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-devel-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-imap-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mbstring-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-process-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-1.9.3.327-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-debuginfo-1.9.3.327-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-devel-1.9.3.327-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-doc-1.9.3.327-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-ruby-irb-1.9.3.327-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-libs-1.9.3.327-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-tcltk-1.9.3.327-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-actionpack-3.2.8-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-actionpack-doc-3.2.8-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-activemodel-3.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-activemodel-doc-3.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-activerecord-3.2.8-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-activerecord-doc-3.2.8-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-bigdecimal-1.1.0-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-io-console-0.3-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-json-1.5.4-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-minitest-2.5.1-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-railties-3.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-railties-doc-3.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-rake-0.9.2.2-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-rdoc-3.9.4-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-ruby_parser-2.3.1-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-ruby_parser-doc-2.3.1-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygems-1.8.23-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygems-devel-1.8.23-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-actionpack-3.0.13-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-activemodel-3.0.13-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-activemodel-doc-3.0.13-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-activerecord-3.0.13-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-bson-1.8.1-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-mongo-1.8.1-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-mongo-doc-1.8.1-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-auth-remote-user-1.0.5-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-console-1.0.10-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-console-doc-1.0.10-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-controller-1.0.12-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-node-1.0.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-ruby_parser-2.0.4-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-ruby_parser-doc-2.0.4-6.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "graphviz / graphviz-debuginfo / graphviz-devel / graphviz-doc / etc");
  }
}
