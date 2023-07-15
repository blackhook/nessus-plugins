#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1168.
#

include("compat.inc");

if (description)
{
  script_id(122674);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2018-12405", "CVE-2018-17466", "CVE-2018-18492", "CVE-2018-18493", "CVE-2018-18494", "CVE-2018-18498");
  script_xref(name:"ALAS", value:"2019-1168");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2019-1168)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A buffer overflow can occur in the Skia library during buffer offset
calculations with hardware accelerated canvas 2D actions due to the
use of 32-bit calculations instead of 64-bit. This results in a
potentially exploitable crash. This vulnerability affects Thunderbird
< 60.4, Firefox ESR < 60.4, and Firefox < 64.(CVE-2018-18493)

A same-origin policy violation allowing the theft of cross-origin URL
entries when using the Javascript location property to cause a
redirection to another site using performance.getEntries(). This is a
same-origin policy violation and could allow for data theft. This
vulnerability affects Thunderbird < 60.4, Firefox ESR < 60.4, and
Firefox < 64.(CVE-2018-18494)

Incorrect texture handling in Angle in Google Chrome prior to
70.0.3538.67 allowed a remote attacker to perform an out of bounds
memory read via a crafted HTML page.(CVE-2018-17466)

Mozilla developers and community members reported memory safety bugs
present in Firefox 63 and Firefox ESR 60.3. Some of these bugs showed
evidence of memory corruption and we presume that with enough effort
that some of these could be exploited to run arbitrary code. This
vulnerability affects Thunderbird < 60.4, Firefox ESR < 60.4, and
Firefox < 64.(CVE-2018-12405)

A use-after-free vulnerability can occur after deleting a selection
element due to a weak reference to the select element in the options
collection. This results in a potentially exploitable crash. This
vulnerability affects Thunderbird < 60.4, Firefox ESR < 60.4, and
Firefox < 64.(CVE-2018-18492)

A potential vulnerability leading to an integer overflow can occur
during buffer size calculations for images when a raw value is used
instead of the checked value. This leads to a possible out-of-bounds
write. This vulnerability affects Thunderbird < 60.4, Firefox ESR <
60.4, and Firefox < 64.(CVE-2018-18498)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1168.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update thunderbird' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-60.5.0-1.amzn2.0.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-debuginfo-60.5.0-1.amzn2.0.1", allowmaj:TRUE)) flag++;

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
