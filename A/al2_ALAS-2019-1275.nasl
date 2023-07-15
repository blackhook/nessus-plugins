#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1275.
#

include("compat.inc");

if (description)
{
  script_id(128289);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_cve_id("CVE-2018-16877", "CVE-2018-16878", "CVE-2019-3885");
  script_xref(name:"ALAS", value:"2019-1275");

  script_name(english:"Amazon Linux 2 : pacemaker (ALAS-2019-1275)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A flaw was found in pacemaker. An insufficient verification inflicted
preference of uncontrolled processes can lead to DoS. (CVE-2018-16878)

A use-after-free flaw was found in pacemaker which could result in
certain sensitive information to be leaked via the system logs.
(CVE-2019-3885)

A flaw was found in the way pacemaker's client-server authentication
was implemented. A local attacker could use this flaw, and combine it
with other IPC weaknesses, to achieve local privilege escalation.
(CVE-2018-16877)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1275.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update pacemaker' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3885");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-cluster-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-nagios-plugins-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/28");
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
if (rpm_check(release:"AL2", reference:"pacemaker-1.1.20-5.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"pacemaker-cli-1.1.20-5.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"pacemaker-cluster-libs-1.1.20-5.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"pacemaker-cts-1.1.20-5.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"pacemaker-debuginfo-1.1.20-5.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"pacemaker-doc-1.1.20-5.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"pacemaker-libs-1.1.20-5.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"pacemaker-libs-devel-1.1.20-5.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"pacemaker-nagios-plugins-metadata-1.1.20-5.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"pacemaker-remote-1.1.20-5.amzn2.0.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pacemaker / pacemaker-cli / pacemaker-cluster-libs / pacemaker-cts / etc");
}
