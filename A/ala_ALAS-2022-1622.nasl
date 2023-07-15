##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2022-1622.
##

include('compat.inc');

if (description)
{
  script_id(163870);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/30");

  script_cve_id(
    "CVE-2020-28007",
    "CVE-2020-28008",
    "CVE-2020-28009",
    "CVE-2020-28010",
    "CVE-2020-28011",
    "CVE-2020-28012",
    "CVE-2020-28013",
    "CVE-2020-28014",
    "CVE-2020-28019",
    "CVE-2020-28022",
    "CVE-2020-28023",
    "CVE-2020-28024",
    "CVE-2020-28025",
    "CVE-2020-28026",
    "CVE-2021-27216"
  );
  script_xref(name:"IAVA", value:"2021-A-0216-S");

  script_name(english:"Amazon Linux AMI : exim (ALAS-2022-1622)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of exim installed on the remote host is prior to 4.92-1.33. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2022-1622 advisory.

  - Exim 4 before 4.94.2 allows Execution with Unnecessary Privileges. Because Exim operates as root in the
    log directory (owned by a non-root user), a symlink or hard link attack allows overwriting critical root-
    owned files anywhere on the filesystem. (CVE-2020-28007)

  - Exim 4 before 4.94.2 allows Execution with Unnecessary Privileges. Because Exim operates as root in the
    spool directory (owned by a non-root user), an attacker can write to a /var/spool/exim4/input spool header
    file, in which a crafted recipient address can indirectly lead to command execution. (CVE-2020-28008)

  - Exim 4 before 4.94.2 allows Integer Overflow to Buffer Overflow because get_stdinput allows unbounded
    reads that are accompanied by unbounded increases in a certain size variable. NOTE: exploitation may be
    impractical because of the execution time needed to overflow (multiple days). (CVE-2020-28009)

  - Exim 4 before 4.94.2 allows Out-of-bounds Write because the main function, while setuid root, copies the
    current working directory pathname into a buffer that is too small (on some common platforms).
    (CVE-2020-28010)

  - Exim 4 before 4.94.2 allows Heap-based Buffer Overflow in queue_run via two sender options: -R and -S.
    This may cause privilege escalation from exim to root. (CVE-2020-28011)

  - Exim 4 before 4.94.2 allows Exposure of File Descriptor to Unintended Control Sphere because rda_interpret
    uses a privileged pipe that lacks a close-on-exec flag. (CVE-2020-28012)

  - Exim 4 before 4.94.2 allows Heap-based Buffer Overflow because it mishandles -F '.(' on the command
    line, and thus may allow privilege escalation from any user to root. This occurs because of the
    interpretation of negative sizes in strncpy. (CVE-2020-28013)

  - Exim 4 before 4.94.2 allows Execution with Unnecessary Privileges. The -oP option is available to the exim
    user, and allows a denial of service because root-owned files can be overwritten. (CVE-2020-28014)

  - Exim 4 before 4.94.2 has Improper Initialization that can lead to recursion-based stack consumption or
    other consequences. This occurs because use of certain getc functions is mishandled when a client uses
    BDAT instead of DATA. (CVE-2020-28019)

  - Exim 4 before 4.94.2 has Improper Restriction of Write Operations within the Bounds of a Memory Buffer.
    This occurs when processing name=value pairs within MAIL FROM and RCPT TO commands. (CVE-2020-28022)

  - Exim 4 before 4.94.2 allows Out-of-bounds Read. smtp_setup_msg may disclose sensitive information from
    process memory to an unauthenticated SMTP client. (CVE-2020-28023)

  - Exim 4 before 4.94.2 allows Buffer Underwrite that may result in unauthenticated remote attackers
    executing arbitrary commands, because smtp_ungetc was only intended to push back characters, but can
    actually push back non-character error codes such as EOF. (CVE-2020-28024)

  - Exim 4 before 4.94.2 allows Out-of-bounds Read because pdkim_finish_bodyhash does not validate the
    relationship between sig->bodyhash.len and b->bh.len; thus, a crafted DKIM-Signature header might lead to
    a leak of sensitive information from process memory. (CVE-2020-28025)

  - Exim 4 before 4.94.2 has Improper Neutralization of Line Delimiters, relevant in non-default
    configurations that enable Delivery Status Notification (DSN). Certain uses of ORCPT= can place a newline
    into a spool header file, and indirectly allow unauthenticated remote attackers to execute arbitrary
    commands as root. (CVE-2020-28026)

  - Exim 4 before 4.94.2 has Execution with Unnecessary Privileges. By leveraging a delete_pid_file race
    condition, a local user can delete arbitrary files as root. This involves the -oP and -oPX options.
    (CVE-2021-27216)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2022-1622.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28007.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28008.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28009.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28010.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28011.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28012.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28013.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28014.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28019.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28022.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28023.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28024.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28025.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28026.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-27216.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update exim' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28026");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-greylist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'exim-4.92-1.33.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exim-4.92-1.33.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exim-debuginfo-4.92-1.33.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exim-debuginfo-4.92-1.33.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exim-greylist-4.92-1.33.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exim-greylist-4.92-1.33.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exim-mon-4.92-1.33.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exim-mon-4.92-1.33.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exim-mysql-4.92-1.33.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exim-mysql-4.92-1.33.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exim-pgsql-4.92-1.33.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'exim-pgsql-4.92-1.33.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim / exim-debuginfo / exim-greylist / etc");
}