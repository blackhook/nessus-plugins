#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1144.
#

include("compat.inc");

if (description)
{
  script_id(121053);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/02");

  script_cve_id("CVE-2018-15688");
  script_xref(name:"ALAS", value:"2019-1144");

  script_name(english:"Amazon Linux 2 : NetworkManager (ALAS-2019-1144)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that systemd-network does not correctly keep track
of a buffer size when constructing DHCPv6 packets. This flaw may lead
to an integer underflow that can be used to produce an heap-based
buffer overflow. A malicious host on the same network segment as the
victim's one may advertise itself as a DHCPv6 server and exploit this
flaw to cause a Denial of Service or potentially gain code execution
on the victim's machine.(CVE-2018-15688)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1144.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update NetworkManager' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15688");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-adsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-config-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-dispatcher-routing-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-libnm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-libnm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-ppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:NetworkManager-wwan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"NetworkManager-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-adsl-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-bluetooth-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-config-server-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-debuginfo-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-dispatcher-routing-rules-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-glib-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-glib-devel-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-libnm-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-libnm-devel-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-ppp-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-team-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-tui-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-wifi-1.12.0-8.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"NetworkManager-wwan-1.12.0-8.amzn2.0.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager / NetworkManager-adsl / NetworkManager-bluetooth / etc");
}
