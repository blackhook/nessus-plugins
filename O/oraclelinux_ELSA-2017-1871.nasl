#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:1871 and 
# Oracle Linux Security Advisory ELSA-2017-1871 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102287);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-0261", "CVE-2015-2153", "CVE-2015-2154", "CVE-2015-2155", "CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7924", "CVE-2016-7925", "CVE-2016-7926", "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7929", "CVE-2016-7930", "CVE-2016-7931", "CVE-2016-7932", "CVE-2016-7933", "CVE-2016-7934", "CVE-2016-7935", "CVE-2016-7936", "CVE-2016-7937", "CVE-2016-7938", "CVE-2016-7939", "CVE-2016-7940", "CVE-2016-7973", "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984", "CVE-2016-7985", "CVE-2016-7986", "CVE-2016-7992", "CVE-2016-7993", "CVE-2016-8574", "CVE-2016-8575", "CVE-2017-5202", "CVE-2017-5203", "CVE-2017-5204", "CVE-2017-5205", "CVE-2017-5341", "CVE-2017-5342", "CVE-2017-5482", "CVE-2017-5483", "CVE-2017-5484", "CVE-2017-5485", "CVE-2017-5486");
  script_xref(name:"RHSA", value:"2017:1871");

  script_name(english:"Oracle Linux 7 : tcpdump (ELSA-2017-1871)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:1871 :

An update for tcpdump is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The tcpdump packages contain the tcpdump utility for monitoring
network traffic. The tcpdump utility can capture and display the
packet headers on a particular network interface or on all interfaces.

The following packages have been upgraded to a later upstream version:
tcpdump (4.9.0). (BZ#1422473)

Security Fix(es) :

* Multiple out of bounds read and integer overflow vulnerabilities
were found in tcpdump affecting the decoding of various protocols. An
attacker could create a crafted pcap file or send specially crafted
packets to the network segment where tcpdump is running in live
capture mode (without -w) which could cause it to display incorrect
data, crash or enter an infinite loop. (CVE-2015-0261, CVE-2015-2153,
CVE-2015-2154, CVE-2015-2155, CVE-2016-7922, CVE-2016-7923,
CVE-2016-7924, CVE-2016-7925, CVE-2016-7926, CVE-2016-7927,
CVE-2016-7928, CVE-2016-7929, CVE-2016-7930, CVE-2016-7931,
CVE-2016-7932, CVE-2016-7933, CVE-2016-7934, CVE-2016-7935,
CVE-2016-7936, CVE-2016-7937, CVE-2016-7938, CVE-2016-7939,
CVE-2016-7940, CVE-2016-7973, CVE-2016-7974, CVE-2016-7975,
CVE-2016-7983, CVE-2016-7984, CVE-2016-7985, CVE-2016-7986,
CVE-2016-7992, CVE-2016-7993, CVE-2016-8574, CVE-2016-8575,
CVE-2017-5202, CVE-2017-5203, CVE-2017-5204, CVE-2017-5205,
CVE-2017-5341, CVE-2017-5342, CVE-2017-5482, CVE-2017-5483,
CVE-2017-5484, CVE-2017-5485, CVE-2017-5486)

Red Hat would like to thank the Tcpdump project for reporting
CVE-2016-7922, CVE-2016-7923, CVE-2016-7924, CVE-2016-7925,
CVE-2016-7926, CVE-2016-7927, CVE-2016-7928, CVE-2016-7929,
CVE-2016-7930, CVE-2016-7931, CVE-2016-7932, CVE-2016-7933,
CVE-2016-7934, CVE-2016-7935, CVE-2016-7936, CVE-2016-7937,
CVE-2016-7938, CVE-2016-7939, CVE-2016-7940, CVE-2016-7973,
CVE-2016-7974, CVE-2016-7975, CVE-2016-7983, CVE-2016-7984,
CVE-2016-7985, CVE-2016-7986, CVE-2016-7992, CVE-2016-7993,
CVE-2016-8574, CVE-2016-8575, CVE-2017-5202, CVE-2017-5203,
CVE-2017-5204, CVE-2017-5205, CVE-2017-5341, CVE-2017-5342,
CVE-2017-5482, CVE-2017-5483, CVE-2017-5484, CVE-2017-5485, and
CVE-2017-5486.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.4 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-August/007078.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tcpdump package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tcpdump-4.9.0-5.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpdump");
}
