#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1912 and 
# CentOS Errata and Security Advisory 2014:1912 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79643);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-4975", "CVE-2014-8080", "CVE-2014-8090");
  script_bugtraq_id(68474, 70935, 71230);
  script_xref(name:"RHSA", value:"2014:1912");

  script_name(english:"CentOS 7 : ruby (CESA-2014:1912)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix three security issues are now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to perform system
management tasks.

Multiple denial of service flaws were found in the way the Ruby REXML
XML parser performed expansion of parameter entities. A specially
crafted XML document could cause REXML to use an excessive amount of
CPU and memory. (CVE-2014-8080, CVE-2014-8090)

A stack-based buffer overflow was found in the implementation of the
Ruby Array pack() method. When performing base64 encoding, a single
byte could be written past the end of the buffer, possibly causing
Ruby to crash. (CVE-2014-4975)

The CVE-2014-8090 issue was discovered by Red Hat Product Security.

All ruby users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All running
instances of Ruby need to be restarted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-December/020792.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13f8376b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-4975");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-devel-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-doc-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-irb-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-libs-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-tcltk-2.0.0.353-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-bigdecimal-1.2.0-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-io-console-0.4.2-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-json-1.7.7-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-minitest-4.3.2-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-psych-2.0.0-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-rake-0.9.6-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygem-rdoc-4.0.0-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygems-2.0.14-22.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rubygems-devel-2.0.14-22.el7_0")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-devel / ruby-doc / ruby-irb / ruby-libs / ruby-tcltk / etc");
}
