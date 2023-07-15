#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1021.
#

include("compat.inc");

if (description)
{
  script_id(110194);
  script_version("1.8");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2018-1111");
  script_xref(name:"ALAS", value:"2018-1021");
  script_xref(name:"IAVA", value:"2018-A-0162");

  script_name(english:"Amazon Linux 2 : dhcp (ALAS-2018-1021)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Command injection vulnerability in the DHCP client NetworkManager
integration script :

A command injection flaw was found in the NetworkManager integration
script included in the DHCP client packages in Amazon Linux 2. A
malicious DHCP server, or an attacker on the local network able to
spoof DHCP responses, could use this flaw to execute arbitrary
commands with root privileges on systems using NetworkManager and
configured to obtain network configuration using the DHCP protocol.
(CVE-2018-1111)

Note: Amazon Linux 2 does not use NetworkManager by default, however
it is recommended to install this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1021.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update dhcp' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'DHCP Client Command Injection (DynoRoot)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"dhclient-4.2.5-68.amzn2.1.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"dhcp-4.2.5-68.amzn2.1.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"dhcp-common-4.2.5-68.amzn2.1.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"dhcp-debuginfo-4.2.5-68.amzn2.1.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"dhcp-devel-4.2.5-68.amzn2.1.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"dhcp-libs-4.2.5-68.amzn2.1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient / dhcp / dhcp-common / dhcp-debuginfo / dhcp-devel / etc");
}
