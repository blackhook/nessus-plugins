#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1429.
#

include('compat.inc');

if (description)
{
  script_id(136752);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-12387",
    "CVE-2020-12392",
    "CVE-2020-12395",
    "CVE-2020-12397",
    "CVE-2020-6819",
    "CVE-2020-6820",
    "CVE-2020-6821",
    "CVE-2020-6822",
    "CVE-2020-6825",
    "CVE-2020-6831"
  );
  script_xref(name:"ALAS", value:"2020-1429");
  script_xref(name:"IAVA", value:"2020-A-0190-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0032");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2020-1429)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Mozilla Foundation Security Advisory describes this flaw as :

On 32-bit builds, an out of bounds write could have occurred when
processing an image larger than 4 GB in 'GMPDecodeData'. It is
possible that with enough effort this could have been exploited to run
arbitrary code. This vulnerability affects Thunderbird < 68.7.0,
Firefox ESR < 68.7, and Firefox < 75. (CVE-2020-6822)

A flaw was found in Mozilla Firefox and Thunderbird. When parsing and
validating SCTP chunks in WebRTC a memory buffer overflow could occur
leading to memory corruption and an exploitable crash. The highest
threat from this vulnerability is to data confidentiality and
integrity as well as system availability. (CVE-2020-6831)

Under certain conditions, when handling a ReadableStream, a race
condition can cause a use-after-free. We are aware of targeted attacks
in the wild abusing this flaw. This vulnerability affects Thunderbird
< 68.7.0, Firefox < 74.0.1, and Firefox ESR < 68.6.1. (CVE-2020-6820)

Under certain conditions, when running the nsDocShell destructor, a
race condition can cause a use-after-free. We are aware of targeted
attacks in the wild abusing this flaw. This vulnerability affects
Thunderbird < 68.7.0, Firefox < 74.0.1, and Firefox ESR < 68.6.1.
(CVE-2020-6819)

The Mozilla Foundation Security Advisory describes this flaw as :

Mozilla developers reported memory safety bugs present in Firefox 74
and Firefox ESR 68.6. Some of these bugs showed evidence of memory
corruption and we presume that with enough effort some of these could
have been exploited to run arbitrary code. This vulnerability affects
Thunderbird < 68.7.0, Firefox ESR < 68.7, and Firefox < 75.
(CVE-2020-6825)

The Mozilla Foundation Security Advisory describes this flaw as :

The 'Copy as cURL' feature of Devtools' network tab did not properly
escape the HTTP POST data of a request, which can be controlled by the
website. If a user used the 'Copy as cURL' feature and pasted the
command into a terminal, it could have resulted in the disclosure of
local files. (CVE-2020-12392)

When reading from areas partially or fully outside the source resource
with WebGL's 'copyTexSubImage' method, the specification requires the
returned values be zero. Previously, this memory was uninitialized,
leading to potentially sensitive data disclosure. This vulnerability
affects Thunderbird < 68.7.0, Firefox ESR < 68.7, and Firefox < 75.
(CVE-2020-6821)

Mozilla: Sender Email Address Spoofing using encoded Unicode
characters (CVE-2020-12397)

Memory safety flaws were found in Mozilla Firefox and Thunderbird.
Memory corruption that an attacker could leverage with enough effort,
could allow arbitrary code to run. The highest threat from this
vulnerability is to data confidentiality and integrity as well as
system availability. (CVE-2020-12395)

A flaw was found in Mozilla Firefox and Thunderbird. When running
shutdown code for Web Worker, a race condition occurs leading to a
use-after-free memory flaw that could lead to an exploitable crash.
The highest threat from this vulnerability is to data confidentiality
and integrity as well as system availability. (CVE-2020-12387)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1429.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update thunderbird' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12395");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6831");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-68.8.0-1.amzn2", allowmaj:TRUE)) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-debuginfo-68.8.0-1.amzn2", allowmaj:TRUE)) flag++;

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
