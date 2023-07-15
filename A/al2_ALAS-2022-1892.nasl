#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1892.
##

include('compat.inc');

if (description)
{
  script_id(168438);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id(
    "CVE-2020-14093",
    "CVE-2020-14154",
    "CVE-2020-14954",
    "CVE-2020-28896",
    "CVE-2021-3181",
    "CVE-2022-1328"
  );

  script_name(english:"Amazon Linux 2 : mutt (ALAS-2022-1892)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of mutt installed on the remote host is prior to 1.5.21-29. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2022-1892 advisory.

  - Mutt before 1.14.3 allows an IMAP fcc/postpone man-in-the-middle attack via a PREAUTH response.
    (CVE-2020-14093)

  - Mutt before 1.14.3 proceeds with a connection even if, in response to a GnuTLS certificate prompt, the
    user rejects an expired intermediate certificate. (CVE-2020-14154)

  - Mutt before 1.14.4 and NeoMutt before 2020-06-19 have a STARTTLS buffering issue that affects IMAP, SMTP,
    and POP3. When a server sends a begin TLS response, the client reads additional data (e.g., from a man-
    in-the-middle attacker) and evaluates it in a TLS context, aka response injection. (CVE-2020-14954)

  - Mutt before 2.0.2 and NeoMutt before 2020-11-20 did not ensure that $ssl_force_tls was processed if an
    IMAP server's initial server response was invalid. The connection was not properly closed, and the code
    could continue attempting to authenticate. This could result in authentication credentials being exposed
    on an unencrypted connection, or to a machine-in-the-middle. (CVE-2020-28896)

  - rfc822.c in Mutt through 2.0.4 allows remote attackers to cause a denial of service (mailbox
    unavailability) by sending email messages with sequences of semicolon characters in RFC822 address fields
    (aka terminators of empty groups). A small email message from the attacker can cause large memory
    consumption, and the victim may then be unable to see email messages from other persons. (CVE-2021-3181)

  - Buffer Overflow in uudecoder in Mutt affecting all versions starting from 0.94.13 before 2.2.3 allows read
    past end of input line (CVE-2022-1328)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1892.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-14093.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-14154.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-14954.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-28896.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3181.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1328.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update mutt' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14154");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14954");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mutt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mutt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'mutt-1.5.21-29.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutt-1.5.21-29.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutt-1.5.21-29.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutt-debuginfo-1.5.21-29.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutt-debuginfo-1.5.21-29.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutt-debuginfo-1.5.21-29.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mutt / mutt-debuginfo");
}