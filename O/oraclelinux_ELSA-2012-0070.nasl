#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0070 and 
# Oracle Linux Security Advisory ELSA-2012-0070 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68441);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-3009", "CVE-2011-4815");
  script_bugtraq_id(49126, 51198);
  script_xref(name:"RHSA", value:"2012:0070");

  script_name(english:"Oracle Linux 4 / 5 : ruby (ELSA-2012-0070)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0070 :

Updated ruby packages that fix two security issues are now available
for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

A denial of service flaw was found in the implementation of
associative arrays (hashes) in Ruby. An attacker able to supply a
large number of inputs to a Ruby application (such as HTTP POST
request parameters sent to a web application) that are used as keys
when inserting data into an array could trigger multiple hash function
collisions, making array operations take an excessive amount of CPU
time. To mitigate this issue, randomization has been added to the hash
function to reduce the chance of an attacker successfully causing
intentional collisions. (CVE-2011-4815)

It was found that Ruby did not reinitialize the PRNG (pseudorandom
number generator) after forking a child process. This could eventually
lead to the PRNG returning the same result twice. An attacker keeping
track of the values returned by one child process could use this flaw
to predict the values the PRNG would return in other child processes
(as long as the parent process persisted). (CVE-2011-3009)

Red Hat would like to thank oCERT for reporting CVE-2011-4815. oCERT
acknowledges Julian Walde and Alexander Klink as the original
reporters of CVE-2011-4815.

All users of ruby are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-January/002578.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-January/002579.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"irb-1.8.1-18.el4")) flag++;
if (rpm_check(release:"EL4", reference:"ruby-1.8.1-18.el4")) flag++;
if (rpm_check(release:"EL4", reference:"ruby-devel-1.8.1-18.el4")) flag++;
if (rpm_check(release:"EL4", reference:"ruby-docs-1.8.1-18.el4")) flag++;
if (rpm_check(release:"EL4", reference:"ruby-libs-1.8.1-18.el4")) flag++;
if (rpm_check(release:"EL4", reference:"ruby-mode-1.8.1-18.el4")) flag++;
if (rpm_check(release:"EL4", reference:"ruby-tcltk-1.8.1-18.el4")) flag++;

if (rpm_check(release:"EL5", reference:"ruby-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-devel-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-docs-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-irb-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-libs-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-mode-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-rdoc-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-ri-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-tcltk-1.8.5-22.el5_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb / ruby / ruby-devel / ruby-docs / ruby-irb / ruby-libs / etc");
}
