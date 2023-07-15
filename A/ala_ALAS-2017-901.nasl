#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-901.
#

include("compat.inc");

if (description)
{
  script_id(103653);
  script_version("3.4");
  script_cvs_date("Date: 2019/04/10 16:10:16");

  script_cve_id("CVE-2017-14497", "CVE-2017-7558");
  script_xref(name:"ALAS", value:"2017-901");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2017-901)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow was discovered in tpacket_rcv() function in the
Linux kernel since v4.6-rc1 through v4.13. A number of socket-related
syscalls can be made to set up a configuration when each packet
received by a network interface can cause writing up to 10 bytes to a
kernel memory outside of a kernel buffer. This can cause unspecified
kernel data corruption effects, including damage of in-memory and
on-disk XFS data. (CVE-2017-14497)

A kernel data leak due to an out-of-bound read was found in the Linux
kernel in inet_diag_msg_sctp{,l}addr_fill() and sctp_get_sctp_info()
functions present since version 4.7-rc1 through version 4.13. A data
leak happens when these functions fill in sockaddr data structures
used to export socket's diagnostic information. As a result, up to 100
bytes of the slab data could be leaked to a userspace. (CVE-2017-7558)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-901.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"kernel-4.9.51-10.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.9.51-10.52.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.9.51-10.52.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.9.51-10.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.9.51-10.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.9.51-10.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.9.51-10.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.9.51-10.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.9.51-10.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.9.51-10.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.9.51-10.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.9.51-10.52.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
