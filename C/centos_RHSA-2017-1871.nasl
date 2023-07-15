#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1871 and 
# CentOS Errata and Security Advisory 2017:1871 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102742);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-0261", "CVE-2015-2153", "CVE-2015-2154", "CVE-2015-2155", "CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7924", "CVE-2016-7925", "CVE-2016-7926", "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7929", "CVE-2016-7930", "CVE-2016-7931", "CVE-2016-7932", "CVE-2016-7933", "CVE-2016-7934", "CVE-2016-7935", "CVE-2016-7936", "CVE-2016-7937", "CVE-2016-7938", "CVE-2016-7939", "CVE-2016-7940", "CVE-2016-7973", "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984", "CVE-2016-7985", "CVE-2016-7986", "CVE-2016-7992", "CVE-2016-7993", "CVE-2016-8574", "CVE-2016-8575", "CVE-2017-5202", "CVE-2017-5203", "CVE-2017-5204", "CVE-2017-5205", "CVE-2017-5341", "CVE-2017-5342", "CVE-2017-5482", "CVE-2017-5483", "CVE-2017-5484", "CVE-2017-5485", "CVE-2017-5486");
  script_xref(name:"RHSA", value:"2017:1871");

  script_name(english:"CentOS 7 : tcpdump (CESA-2017:1871)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for tcpdump is now available for Red Hat Enterprise Linux 7.

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
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004570.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47dc971b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tcpdump package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0261");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tcpdump-4.9.0-5.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpdump");
}
