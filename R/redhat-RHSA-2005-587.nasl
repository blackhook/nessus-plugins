#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:587. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19285);
  script_version("1.32");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2004-0718", "CVE-2005-1937", "CVE-2005-2114", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2263", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
  script_xref(name:"RHSA", value:"2005:587");

  script_name(english:"RHEL 2.1 / 3 / 4 : mozilla (RHSA-2005:587)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mozilla packages that fix various security issues are now
available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

A bug was found in the way Mozilla handled synthetic events. It is
possible that Web content could generate events such as keystrokes or
mouse clicks that could be used to steal data or execute malicious
JavaScript code. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-2260 to this issue.

A bug was found in the way Mozilla executed JavaScript in XBL
controls. It is possible for a malicious webpage to leverage this
vulnerability to execute other JavaScript based attacks even when
JavaScript is disabled. (CVE-2005-2261)

A bug was found in the way Mozilla installed its extensions. If a user
can be tricked into visiting a malicious webpage, it may be possible
to obtain sensitive information such as cookies or passwords.
(CVE-2005-2263)

A bug was found in the way Mozilla handled certain JavaScript
functions. It is possible for a malicious webpage to crash the browser
by executing malformed JavaScript code. (CVE-2005-2265)

A bug was found in the way Mozilla handled multiple frame domains. It
is possible for a frame as part of a malicious website to inject
content into a frame that belongs to another domain. This issue was
previously fixed as CVE-2004-0718 but was accidentally disabled.
(CVE-2005-1937)

A bug was found in the way Mozilla handled child frames. It is
possible for a malicious framed page to steal sensitive information
from its parent page. (CVE-2005-2266)

A bug was found in the way Mozilla opened URLs from media players. If
a media player opens a URL which is JavaScript, the JavaScript
executes with access to the currently open webpage. (CVE-2005-2267)

A design flaw was found in the way Mozilla displayed alerts and
prompts. Alerts and prompts were given the generic title [JavaScript
Application] which prevented a user from knowing which site created
them. (CVE-2005-2268)

A bug was found in the way Mozilla handled DOM node names. It is
possible for a malicious site to overwrite a DOM node name, allowing
certain privileged chrome actions to execute the malicious JavaScript.
(CVE-2005-2269)

A bug was found in the way Mozilla cloned base objects. It is possible
for Web content to traverse the prototype chain to gain access to
privileged chrome objects. (CVE-2005-2270)

Users of Mozilla are advised to upgrade to these updated packages,
which contain Mozilla version 1.7.10 and are not vulnerable to these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-1937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2005:587"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^(2\.1|3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:587";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"galeon-1.2.14-1.2.6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-1.7.10-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-chat-1.7.10-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-devel-1.7.10-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-dom-inspector-1.7.10-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-js-debugger-1.7.10-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-mail-1.7.10-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-1.7.10-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-devel-1.7.10-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-1.7.10-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-devel-1.7.10-1.1.2.1")) flag++;

  if (rpm_check(release:"RHEL3", reference:"mozilla-1.7.10-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-chat-1.7.10-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-devel-1.7.10-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-dom-inspector-1.7.10-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-js-debugger-1.7.10-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-mail-1.7.10-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-1.7.10-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-devel-1.7.10-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-1.7.10-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-devel-1.7.10-1.1.3.1")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"devhelp-0.9.2-2.4.6")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"devhelp-0.9.2-2.4.6")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"devhelp-devel-0.9.2-2.4.6")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"devhelp-devel-0.9.2-2.4.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-1.7.10-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-chat-1.7.10-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-devel-1.7.10-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-dom-inspector-1.7.10-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-js-debugger-1.7.10-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-mail-1.7.10-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nspr-1.7.10-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nspr-devel-1.7.10-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nss-1.7.10-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nss-devel-1.7.10-1.4.1")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / galeon / mozilla / mozilla-chat / etc");
  }
}
