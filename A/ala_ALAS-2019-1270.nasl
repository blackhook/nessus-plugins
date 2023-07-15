#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1270.
#

include("compat.inc");

if (description)
{
  script_id(128293);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-14809", "CVE-2019-9512", "CVE-2019-9514");
  script_xref(name:"ALAS", value:"2019-1270");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Amazon Linux AMI : golang (ALAS-2019-1270) (Ping Flood) (Reset Flood)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"net/url in Go before 1.11.13 and 1.12.x before 1.12.8 mishandles
malformed hosts in URLs, leading to an authorization bypass in some
applications. This is related to a Host field with a suffix appearing
in neither Hostname() nor Port(), and is related to a non-numeric port
number. For example, an attacker can compose a crafted javascript://
URL that results in a hostname of google.com. (CVE-2019-14809)

Some HTTP/2 implementations are vulnerable to ping floods, potentially
leading to a denial of service. The attacker sends continual pings to
an HTTP/2 peer, causing the peer to build an internal queue of
responses. Depending on how efficiently this data is queued, this can
consume excess CPU, memory, or both.(CVE-2019-9512)

Some HTTP/2 implementations are vulnerable to a reset flood,
potentially leading to a denial of service. The attacker opens a
number of streams and sends an invalid request over each stream that
should solicit a stream of RST_STREAM frames from the peer. Depending
on how the peer queues the RST_STREAM frames, this can consume excess
memory, CPU, or both.(CVE-2019-9514)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1270.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update golang' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14809");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/28");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"golang-1.12.8-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-bin-1.12.8-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-docs-1.12.8-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-misc-1.12.8-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"golang-race-1.12.8-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-src-1.12.8-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-tests-1.12.8-1.51.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "golang / golang-bin / golang-docs / golang-misc / golang-race / etc");
}
