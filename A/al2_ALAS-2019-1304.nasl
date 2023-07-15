#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1304.
#

include("compat.inc");

if (description)
{
  script_id(129562);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2019-11739", "CVE-2019-11740", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11752");
  script_xref(name:"ALAS", value:"2019-1304");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2019-1304)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Encrypted S/MIME parts in a crafted multipart/alternative message can
leak plaintext when included in a a HTML reply/forward. This
vulnerability affects Thunderbird < 68.1 and Thunderbird < 60.9.
(CVE-2019-11739)

A same-origin policy violation occurs allowing the theft of
cross-origin images through a combination of SVG filters and a
<canvas> element due to an error in how same-origin policy is applied
to cached image content. The resulting same-origin policy violation
could allow for data theft. This vulnerability affects Firefox < 69,
Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and
Firefox ESR < 68.1. (CVE-2019-11742)

A use-after-free vulnerability can occur while manipulating video
elements if the body is freed while still in use. This results in a
potentially exploitable crash. This vulnerability affects Firefox <
69, Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and
Firefox ESR < 68.1. (CVE-2019-11746)

It is possible to delete an IndexedDB key value and subsequently try
to extract it during conversion. This results in a use-after-free and
a potentially exploitable crash. This vulnerability affects Firefox <
69, Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and
Firefox ESR < 68.1. (CVE-2019-11752)

Some HTML elements, such as <title> and <textarea>, can contain
literal angle brackets without treating them as markup. It is possible
to pass a literal closing tag to .innerHTML on these elements, and
subsequent content after that will be parsed as if it were outside the
tag. This can lead to XSS if a site does not filter user input as
strictly for these elements as it does for other elements. This
vulnerability affects Firefox < 69, Thunderbird < 68.1, Thunderbird <
60.9, Firefox ESR < 60.9, and Firefox ESR < 68.1. (CVE-2019-11744)

Mozilla developers and community members reported memory safety bugs
present in Firefox 68, Firefox ESR 68, and Firefox 60.8. Some of these
bugs showed evidence of memory corruption and we presume that with
enough effort that some of these could be exploited to run arbitrary
code. This vulnerability affects Firefox < 69, Thunderbird < 68.1,
Thunderbird < 60.9, Firefox ESR < 60.9, and Firefox ESR < 68.1.
(CVE-2019-11740)

Navigation events were not fully adhering to the W3C's
'Navigation-Timing Level 2' draft specification in some instances for
the unload event, which restricts access to detailed timing attributes
to only be same-origin. This resulted in potential cross-origin
information exposure of history through timing side-channel attacks.
This vulnerability affects Firefox < 69, Thunderbird < 68.1,
Thunderbird < 60.9, Firefox ESR < 60.9, and Firefox ESR < 68.1.
(CVE-2019-11743)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1304.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update thunderbird' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11752");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/04");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-60.9.0-1.amzn2.0.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-debuginfo-60.9.0-1.amzn2.0.1", allowmaj:TRUE)) flag++;

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
