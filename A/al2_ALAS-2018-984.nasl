#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-984.
#

include("compat.inc");

if (description)
{
  script_id(109137);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

  script_cve_id("CVE-2018-5732", "CVE-2018-5733");
  script_xref(name:"ALAS", value:"2018-984");
  script_xref(name:"IAVB", value:"2018-B-0034-S");

  script_name(english:"Amazon Linux 2 : dhcp (ALAS-2018-984)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Buffer overflow in dhclient possibly allowing code execution triggered
by malicious server

An out-of-bound memory access flaw was found in the way dhclient
processed a DHCP response packet. A malicious DHCP server could
potentially use this flaw to crash dhclient processes running on DHCP
client machines via a crafted DHCP response packet. (CVE-2018-5732)

Reference count overflow in dhcpd allows denial of service

A denial of service flaw was found in the way dhcpd handled reference
counting when processing client requests. A malicious DHCP client
could use this flaw to trigger a reference count overflow on the
server side, potentially causing dhcpd to crash, by sending large
amounts of traffic. (CVE-2018-5733)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-984.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update dhcp' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"dhclient-4.2.5-58.amzn2.3.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"dhcp-4.2.5-58.amzn2.3.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"dhcp-common-4.2.5-58.amzn2.3.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"dhcp-debuginfo-4.2.5-58.amzn2.3.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"dhcp-devel-4.2.5-58.amzn2.3.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"dhcp-libs-4.2.5-58.amzn2.3.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient / dhcp / dhcp-common / dhcp-debuginfo / dhcp-devel / etc");
}
