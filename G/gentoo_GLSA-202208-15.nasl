#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-15.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164046);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/11");

  script_cve_id(
    "CVE-2021-3578",
    "CVE-2021-3657",
    "CVE-2021-20247",
    "CVE-2021-44143"
  );

  script_name(english:"GLSA-202208-15 : isync: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-15 (isync: Multiple Vulnerabilities)

  - A flaw was found in mbsync before v1.3.5 and v1.4.1. Validations of the mailbox names returned by IMAP
    LIST/LSUB do not occur allowing a malicious or compromised server to use specially crafted mailbox names
    containing '..' path components to access data outside the designated mailbox on the opposite end of the
    synchronization channel. The highest threat from this vulnerability is to data confidentiality and
    integrity. (CVE-2021-20247)

  - A flaw was found in mbsync before v1.3.6 and v1.4.2, where an unchecked pointer cast allows a malicious or
    compromised server to write an arbitrary integer value past the end of a heap-allocated structure by
    issuing an unexpected APPENDUID response. This could be plausibly exploited for remote code execution on
    the client. (CVE-2021-3578)

  - A flaw was found in mbsync versions prior to 1.4.4. Due to inadequate handling of extremely large (>=2GiB)
    IMAP literals, malicious or compromised IMAP servers, and hypothetically even external email senders,
    could cause several different buffer overflows, which could conceivably be exploited for remote code
    execution. (CVE-2021-3657)

  - A flaw was found in mbsync in isync 1.4.0 through 1.4.3. Due to an unchecked condition, a malicious or
    compromised IMAP server could use a crafted mail message that lacks headers (i.e., one that starts with an
    empty line) to provoke a heap overflow, which could conceivably be exploited for remote code execution.
    (CVE-2021-44143)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-15");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=771738");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=794772");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=826902");
  script_set_attribute(attribute:"solution", value:
"All isync users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-mail/isync-1.4.4");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:isync");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "net-mail/isync",
    'unaffected' : make_list("ge 1.4.4"),
    'vulnerable' : make_list("lt 1.4.4")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "isync");
}
