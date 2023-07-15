#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-950.
#

include("compat.inc");

if (description)
{
  script_id(106695);
  script_version("3.4");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2018-5702");
  script_xref(name:"ALAS", value:"2018-950");

  script_name(english:"Amazon Linux AMI : transmission (ALAS-2018-950)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Transmission relies on X-Transmission-Session-Id (which is not a
forbidden header for Fetch) for access control, which allows remote
attackers to execute arbitrary RPC commands, and consequently write to
arbitrary files, via POST requests to /transmission/rpc in conjunction
with a DNS rebinding attack. (CVE-2018-5702)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-950.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update transmission' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:transmission");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:transmission-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:transmission-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:transmission-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:transmission-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");
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
if (rpm_check(release:"ALA", reference:"transmission-2.92-11.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"transmission-cli-2.92-11.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"transmission-common-2.92-11.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"transmission-daemon-2.92-11.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"transmission-debuginfo-2.92-11.12.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "transmission / transmission-cli / transmission-common / etc");
}
