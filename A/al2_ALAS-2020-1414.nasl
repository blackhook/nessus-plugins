#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1414.
#

include("compat.inc");

if (description)
{
  script_id(135932);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2019-20503", "CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6811", "CVE-2020-6812", "CVE-2020-6814");
  script_xref(name:"ALAS", value:"2020-1414");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2020-1414)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Mozilla Foundation Security Advisory describes this flaw as: When
removing data about an origin whose tab was recently closed, a
use-after-free could occur in the Quota manager, resulting in a
potentially exploitable crash. (CVE-2020-6805)

The Mozilla Foundation Security Advisory describes this flaw as: The
inputs to `sctp_load_addresses_from_init` are verified by
`sctp_arethere_unrecognized_parameters`; however, the two functions
handled parameter bounds differently, resulting in out of bounds reads
when parameters are partially outside a chunk. (CVE-2019-20503)

The Mozilla Foundation Security Advisory describes this flaw as: By
carefully crafting promise resolutions, it was possible to cause an
out-of-bounds read off the end of an array resized during script
execution. This could have led to memory corruption and a potentially
exploitable crash. (CVE-2020-6806)

The Mozilla Foundation Security Advisory describes this flaw as: When
a device was changed while a stream was about to be destroyed, the
`stream-reinit` task may have been executed after the stream was
destroyed, causing a use-after-free and a potentially exploitable
crash. (CVE-2020-6807)

The Mozilla Foundation Security Advisory describes this flaw as: The
first time AirPods are connected to an iPhone, they become named after
the user's name by default (e.g. Jane Doe's AirPods.) Websites with
camera or microphone permission are able to enumerate device names,
disclosing the user's name. To resolve this issue, Firefox added a
special case that renames devices containing the substring 'AirPods'
to simply 'AirPods'. (CVE-2020-6812)

The Mozilla Foundation Security Advisory describes this flaw as: The
'Copy as cURL' feature of Devtools' network tab did not properly
escape the HTTP method of a request, which can be controlled by the
website. If a user used the 'Copy as Curl' feature and pasted the
command into a terminal, it could have resulted in command injection
and arbitrary command execution. (CVE-2020-6811)

The Mozilla Foundation Security Advisory describes this flaw as:
Mozilla developers and community members reported memory safety bugs
present in Firefox 73 and Firefox ESR 68.5. Some of these bugs showed
evidence of memory corruption and we presume that with enough effort
some of these could have been exploited to run arbitrary code.
(CVE-2020-6814)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1414.html"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-68.6.0-1.amzn2.0.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-debuginfo-68.6.0-1.amzn2.0.1", allowmaj:TRUE)) flag++;

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
