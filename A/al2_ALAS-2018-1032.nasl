#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1032.
#

include("compat.inc");

if (description)
{
  script_id(110449);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2018-5150", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5159", "CVE-2018-5161", "CVE-2018-5162", "CVE-2018-5168", "CVE-2018-5170", "CVE-2018-5178", "CVE-2018-5183", "CVE-2018-5184", "CVE-2018-5185");
  script_xref(name:"ALAS", value:"2018-1032");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2018-1032)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The following CVEs are fixed in the updated thunderbird package :

CVE-2018-5161 : Hang via malformed headers

CVE-2018-5162 : Encrypted mail leaks plaintext through src attribute

CVE-2018-5183 : Backport critical security fixes in Skia

CVE-2018-5155 : Use-after-free with SVG animations and text paths

CVE-2018-5170 : Filename spoofing for external attachments

CVE-2018-5184 : Full plaintext recovery in S/MIME via
chosen-ciphertext attack

CVE-2018-5159 : Integer overflow and out-of-bounds write in Skia

CVE-2018-5178 : Buffer overflow during UTF-8 to Unicode string
conversion through legacy extension

CVE-2018-5168 : Lightweight themes can be installed without user
interaction

CVE-2018-5150 : Memory safety bugs fixed in Firefox 60 and Firefox ESR
52.8

CVE-2018-5154 : Use-after-free with SVG animations and clip paths

CVE-2018-5185 : Leaking plaintext through HTML forms"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1032.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update thunderbird' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-52.8.0-1.amzn2", allowmaj:TRUE)) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-debuginfo-52.8.0-1.amzn2", allowmaj:TRUE)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}
