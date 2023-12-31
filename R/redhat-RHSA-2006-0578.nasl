#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0578. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22088);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787", "CVE-2006-2788");
  script_xref(name:"RHSA", value:"2006:0578");

  script_name(english:"RHEL 3 : seamonkey (RHSA-2006:0578)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix several security bugs in the
mozilla package are now available for Red Hat Enterprise Linux 3.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

SeaMonkey is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

The Mozilla Foundation has discontinued support for the Mozilla Suite.
This update deprecates the Mozilla Suite in Red Hat Enterprise Linux 3
in favor of the supported SeaMonkey Suite.

This update also resolves a number of outstanding Mozilla security
issues :

Several flaws were found in the way Mozilla processed certain
JavaScript actions. A malicious web page could execute arbitrary
JavaScript instructions with the permissions of 'chrome', allowing the
page to steal sensitive information or install browser malware.
(CVE-2006-2776, CVE-2006-2784, CVE-2006-2785, CVE-2006-2787)

Several denial of service flaws were found in the way Mozilla
processed certain web content. A malicious web page could crash
firefox or possibly execute arbitrary code. These issues to date were
not proven to be exploitable, but do show evidence of memory
corruption. (CVE-2006-2779, CVE-2006-2780)

A double-free flaw was found in the way Mozilla-mail displayed
malformed inline vcard attachments. If a victim viewed an email
message containing a carefully crafted vcard it could execute
arbitrary code as the user running Mozilla-mail. (CVE-2006-2781)

A cross site scripting flaw was found in the way Mozilla processed
Unicode Byte-order-Mark (BOM) markers in UTF-8 web pages. A malicious
web page could execute a script within the browser that a web input
sanitizer could miss due to a malformed 'script' tag. (CVE-2006-2783)

A form file upload flaw was found in the way Mozilla handled
JavaScript input object mutation. A malicious web page could upload an
arbitrary local file at form submission time without user interaction.
(CVE-2006-2782)

A denial of service flaw was found in the way Mozilla called the
crypto.signText() JavaScript function. A malicious web page could
crash the browser if the victim had a client certificate loaded.
(CVE-2006-2778)

Two HTTP response smuggling flaws were found in the way Mozilla
processed certain invalid HTTP response headers. A malicious website
could return specially crafted HTTP response headers which may bypass
HTTP proxy restrictions. (CVE-2006-2786)

A double free flaw was found in the way the nsIX509::getRawDER method
was called. If a victim visited a carefully crafted web page it could
execute arbitrary code as the user running Mozilla. (CVE-2006-2788)

Users of Mozilla are advised to upgrade to this update, which contains
SeaMonkey version 1.0.2 that is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2006:0578"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0578";
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
  if (rpm_check(release:"RHEL3", reference:"seamonkey-1.0.2-0.1.0.EL3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-chat-1.0.2-0.1.0.EL3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-devel-1.0.2-0.1.0.EL3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-dom-inspector-1.0.2-0.1.0.EL3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-js-debugger-1.0.2-0.1.0.EL3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-mail-1.0.2-0.1.0.EL3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nspr-1.0.2-0.1.0.EL3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nspr-devel-1.0.2-0.1.0.EL3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nss-1.0.2-0.1.0.EL3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nss-devel-1.0.2-0.1.0.EL3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-chat / seamonkey-devel / etc");
  }
}
