#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1460. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84952);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2014-8710", "CVE-2014-8711", "CVE-2014-8712", "CVE-2014-8713", "CVE-2014-8714", "CVE-2015-0562", "CVE-2015-0564", "CVE-2015-2189", "CVE-2015-2191");
  script_bugtraq_id(71069, 71070, 71071, 71072, 71073, 71921, 71922, 72941, 72944);
  script_xref(name:"RHSA", value:"2015:1460");

  script_name(english:"RHEL 6 : wireshark (RHSA-2015:1460)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated wireshark packages that fix multiple security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Wireshark, previously known as Ethereal, is a network protocol
analyzer, which is used to capture and browse the traffic running on a
computer network.

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2014-8714,
CVE-2014-8712, CVE-2014-8713, CVE-2014-8711, CVE-2014-8710,
CVE-2015-0562, CVE-2015-0564, CVE-2015-2189, CVE-2015-2191)

This update also fixes the following bugs :

* Previously, the Wireshark tool did not support Advanced Encryption
Standard Galois/Counter Mode (AES-GCM) cryptographic algorithm. As a
consequence, AES-GCM was not decrypted. Support for AES-GCM has been
added to Wireshark, and AES-GCM is now correctly decrypted.
(BZ#1095065)

* Previously, when installing the system using the kickstart method, a
dependency on the shadow-utils packages was missing from the wireshark
packages, which could cause the installation to fail with a 'bad
scriptlet' error message. With this update, shadow-utils are listed as
required in the wireshark packages spec file, and kickstart
installation no longer fails. (BZ#1121275)

* Prior to this update, the Wireshark tool could not decode types of
elliptic curves in Datagram Transport Layer Security (DTLS) Client
Hello. Consequently, Wireshark incorrectly displayed elliptic curves
types as data. A patch has been applied to address this bug, and
Wireshark now decodes elliptic curves types properly. (BZ#1131203)

* Previously, a dependency on the gtk2 packages was missing from the
wireshark packages. As a consequence, the Wireshark tool failed to
start under certain circumstances due to an unresolved symbol,
'gtk_combo_box_text_new_with_entry', which was added in gtk version
2.24. With this update, a dependency on gtk2 has been added, and
Wireshark now always starts as expected. (BZ#1160388)

In addition, this update adds the following enhancements :

* With this update, the Wireshark tool supports process substitution,
which feeds the output of a process (or processes) into the standard
input of another process using the '<(command_list)' syntax. When
using process substitution with large files as input, Wireshark failed
to decode such input. (BZ#1104210)

* Wireshark has been enhanced to enable capturing packets with
nanosecond time stamp precision, which allows better analysis of
recorded network traffic. (BZ#1146578)

All wireshark users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements. All running instances of Wireshark must be restarted for
the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:1460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-2191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-2189"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1460";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL6", reference:"wireshark-1.8.10-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wireshark-debuginfo-1.8.10-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wireshark-devel-1.8.10-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"wireshark-gnome-1.8.10-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"wireshark-gnome-1.8.10-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"wireshark-gnome-1.8.10-17.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-devel / wireshark-gnome");
  }
}
