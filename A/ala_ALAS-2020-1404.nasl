#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1404.
#

include('compat.inc');

if (description)
{
  script_id(139085);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-11080");
  script_xref(name:"ALAS", value:"2020-1404");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Amazon Linux AMI : nghttp2 (ALAS-2020-1404)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"In nghttp2 before version 1.41.0, the overly large HTTP/2 SETTINGS
frame payload causes denial of service. The proof of concept attack
involves a malicious client constructing a SETTINGS frame with a
length of 14,400 bytes (2400 individual settings entries) over and
over again. The attack causes the CPU to spike at 100%. nghttp2
v1.41.0 fixes this vulnerability. There is a workaround to this
vulnerability. Implement nghttp2_on_frame_recv_callback callback, and
if received frame is SETTINGS frame and the number of settings entries
are large (e.g., > 32), then drop the connection. (CVE-2020-11080)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1404.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update nghttp2' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libnghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libnghttp2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nghttp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"ALA", reference:"libnghttp2-1.33.0-1.1.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libnghttp2-devel-1.33.0-1.1.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nghttp2-1.33.0-1.1.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nghttp2-debuginfo-1.33.0-1.1.6.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnghttp2 / libnghttp2-devel / nghttp2 / nghttp2-debuginfo");
}
