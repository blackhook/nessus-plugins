#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:0378 and 
# Oracle Linux Security Advisory ELSA-2018-0378 respectively.
#

include("compat.inc");

if (description)
{
  script_id(107080);
  script_version("3.4");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2017-0898", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-0902", "CVE-2017-0903", "CVE-2017-10784", "CVE-2017-14033", "CVE-2017-14064", "CVE-2017-17405", "CVE-2017-17790");
  script_xref(name:"RHSA", value:"2018:0378");

  script_name(english:"Oracle Linux 7 : ruby (ELSA-2018-0378)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:0378 :

An update for ruby is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to perform system
management tasks.

Security Fix(es) :

* It was discovered that the Net::FTP module did not properly process
filenames in combination with certain operations. A remote attacker
could exploit this flaw to execute arbitrary commands by setting up a
malicious FTP server and tricking a user or Ruby application into
downloading files with specially crafted names using the Net::FTP
module. (CVE-2017-17405)

* A buffer underflow was found in ruby's sprintf function. An
attacker, with ability to control its format string parameter, could
send a specially crafted string that would disclose heap memory or
crash the interpreter. (CVE-2017-0898)

* It was found that rubygems did not sanitize gem names during
installation of a given gem. A specially crafted gem could use this
flaw to install files outside of the regular directory.
(CVE-2017-0901)

* A vulnerability was found where rubygems did not sanitize DNS
responses when requesting the hostname of the rubygems server for a
domain, via a _rubygems._tcp DNS SRV query. An attacker with the
ability to manipulate DNS responses could direct the gem command
towards a different domain. (CVE-2017-0902)

* A vulnerability was found where the rubygems module was vulnerable
to an unsafe YAML deserialization when inspecting a gem. Applications
inspecting gem files without installing them can be tricked to execute
arbitrary code in the context of the ruby interpreter. (CVE-2017-0903)

* It was found that WEBrick did not sanitize all its log messages. If
logs were printed in a terminal, an attacker could interact with the
terminal via the use of escape sequences. (CVE-2017-10784)

* It was found that the decode method of the OpenSSL::ASN1 module was
vulnerable to buffer underrun. An attacker could pass a specially
crafted string to the application in order to crash the ruby
interpreter, causing a denial of service. (CVE-2017-14033)

* A vulnerability was found where rubygems did not properly sanitize
gems' specification text. A specially crafted gem could interact with
the terminal via the use of escape sequences. (CVE-2017-0899)

* It was found that rubygems could use an excessive amount of CPU
while parsing a sufficiently long gem summary. A specially crafted gem
from a gem repository could freeze gem commands attempting to parse
its summary. (CVE-2017-0900)

* A buffer overflow vulnerability was found in the JSON extension of
ruby. An attacker with the ability to pass a specially crafted JSON
input to the extension could use this flaw to expose the interpreter's
heap memory. (CVE-2017-14064)

* The 'lazy_initialize' function in lib/resolv.rb did not properly
process certain filenames. A remote attacker could possibly exploit
this flaw to inject and execute arbitrary commands. (CVE-2017-17790)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-February/007545.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ruby-2.0.0.648-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ruby-devel-2.0.0.648-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ruby-doc-2.0.0.648-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ruby-irb-2.0.0.648-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ruby-libs-2.0.0.648-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ruby-tcltk-2.0.0.648-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"rubygem-bigdecimal-1.2.0-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"rubygem-io-console-0.4.2-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"rubygem-json-1.7.7-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"rubygem-minitest-4.3.2-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"rubygem-psych-2.0.0-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"rubygem-rake-0.9.6-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"rubygem-rdoc-4.0.0-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"rubygems-2.0.14.1-33.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"rubygems-devel-2.0.14.1-33.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-devel / ruby-doc / ruby-irb / ruby-libs / ruby-tcltk / etc");
}
