#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1017.
#

include("compat.inc");

if (description)
{
  script_id(109699);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2014-9402", "CVE-2015-5180", "CVE-2017-12132", "CVE-2017-15670", "CVE-2017-15804", "CVE-2018-1000001");
  script_xref(name:"ALAS", value:"2018-1017");

  script_name(english:"Amazon Linux AMI : glibc (ALAS-2018-1017)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fragmentation attacks possible when EDNS0 is enabled

The DNS stub resolver in the GNU C Library (aka glibc or libc6) before
version 2.26, when EDNS support is enabled, will solicit large UDP
responses from name servers, potentially simplifying off-path DNS
spoofing attacks due to IP fragmentation.(CVE-2017-12132)

Buffer overflow in glob with GLOB_TILDE

The GNU C Library (aka glibc or libc6) before 2.27 contains an
off-by-one error leading to a heap-based buffer overflow in the glob
function in glob.c, related to the processing of home directories
using the ~ operator followed by a long string.(CVE-2017-15670)

Denial of service in getnetbyname function

The nss_dns implementation of getnetbyname in GNU C Library (aka
glibc) before 2.21, when the DNS backend in the Name Service Switch
configuration is enabled, allows remote attackers to cause a denial of
service (infinite loop) by sending a positive answer while a network
name is being process.(CVE-2014-9402)

DNS resolver NULL pointer dereference with crafted record type

res_query in libresolv in glibc before 2.25 allows remote attackers to
cause a denial of service (NULL pointer dereference and process
crash).(CVE-2015-5180)

realpath() buffer underflow when getcwd() returns relative path allows
privilege escalation

In glibc 2.26 and earlier there is confusion in the usage of getcwd()
by realpath() which can be used to write before the destination buffer
leading to a buffer underflow and potential code
execution.(CVE-2018-1000001)

Buffer overflow during unescaping of user names with the ~ operator

The glob function in glob.c in the GNU C Library (aka glibc or libc6)
before 2.27 contains a buffer overflow during unescaping of user names
with the ~ operator.(CVE-2017-15804)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1017.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update glibc' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'glibc "realpath()" Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"glibc-2.17-222.173.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-common-2.17-222.173.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-debuginfo-2.17-222.173.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-debuginfo-common-2.17-222.173.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-devel-2.17-222.173.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-headers-2.17-222.173.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-static-2.17-222.173.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-utils-2.17-222.173.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nscd-2.17-222.173.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
}
