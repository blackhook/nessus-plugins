#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1462. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84953);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2010-5312", "CVE-2012-6662");
  script_bugtraq_id(71106, 71107);
  script_xref(name:"RHSA", value:"2015:1462");

  script_name(english:"RHEL 6 : ipa (RHSA-2015:1462)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated ipa packages that fix two security issues and several bugs are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Identity Management (IdM) is a centralized authentication,
identity management, and authorization solution for both traditional
and cloud-based enterprise environments.

Two cross-site scripting (XSS) flaws were found in jQuery, which
impacted the Identity Management web administrative interface, and
could allow an authenticated user to inject arbitrary HTML or web
script into the interface. (CVE-2010-5312, CVE-2012-6662)

Note: The IdM version provided by this update no longer uses jQuery.

Bug fixes :

* The ipa-server-install, ipa-replica-install, and ipa-client-install
utilities are not supported on machines running in FIPS-140 mode.
Previously, IdM did not warn users about this. Now, IdM does not allow
running the utilities in FIPS-140 mode, and displays an explanatory
message. (BZ#1131571)

* If an Active Directory (AD) server was specified or discovered
automatically when running the ipa-client-install utility, the utility
produced a traceback instead of informing the user that an IdM server
is expected in this situation. Now, ipa-client-install detects the AD
server and fails with an explanatory message. (BZ#1132261)

* When IdM servers were configured to require the TLS protocol version
1.1 (TLSv1.1) or later in the httpd server, the ipa utility failed.
With this update, running ipa works as expected with TLSv1.1 or later.
(BZ#1154687)

* In certain high-load environments, the Kerberos authentication step
of the IdM client installer can fail. Previously, the entire client
installation failed in this situation. This update modifies
ipa-client-install to prefer the TCP protocol over the UDP protocol
and to retry the authentication attempt in case of failure.
(BZ#1161722)

* If ipa-client-install updated or created the /etc/nsswitch.conf
file, the sudo utility could terminate unexpectedly with a
segmentation fault. Now, ipa-client-install puts a new line character
at the end of nsswitch.conf if it modifies the last line of the file,
fixing this bug. (BZ#1185207)

* The ipa-client-automount utility failed with the
'UNWILLING_TO_PERFORM' LDAP error when the nsslapd-minssf Red Hat
Directory Server configuration parameter was set to '1'. This update
modifies ipa-client-automount to use encrypted connection for LDAP
searches by default, and the utility now finishes successfully even
with nsslapd-minssf specified. (BZ#1191040)

* If installing an IdM server failed after the Certificate Authority
(CA) installation, the 'ipa-server-install --uninstall' command did
not perform a proper cleanup. After the user issued
'ipa-server-install --uninstall' and then attempted to install the
server again, the installation failed. Now, 'ipa-server-install
--uninstall' removes the CA-related files in the described situation,
and ipa-server-install no longer fails with the mentioned error
message. (BZ#1198160)

* Running ipa-client-install added the 'sss' entry to the sudoers line
in nsswitch.conf even if 'sss' was already configured and the entry
was present in the file. Duplicate 'sss' then caused sudo to become
unresponsive. Now, ipa-client-install no longer adds 'sss' if it is
already present in nsswitch.conf. (BZ#1198339)

* After running ipa-client-install, it was not possible to log in
using SSH under certain circumstances. Now, ipa-client-install no
longer corrupts the sshd_config file, and the sshd service can start
as expected, and logging in using SSH works in the described
situation. (BZ#1201454)

* An incorrect definition of the dc attribute in the
/usr/share/ipa/05rfc2247.ldif file caused bogus error messages to be
returned during migration. The attribute has been fixed, but the bug
persists if the copy-schema-to-ca.py script was run on Red Hat
Enterprise Linux 6.6 prior to running it on Red Hat Enterprise Linux
6.7. To work around this problem, manually copy
/usr/share/ipa/schema/05rfc2247.ldif to
/etc/dirsrv/slapd-PKI-IPA/schema/ and restart IdM. (BZ#1220788)

All ipa users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:1462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2010-5312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-6662"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/24");
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
  rhsa = "RHSA-2015:1462";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-admintools-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-admintools-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-admintools-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-client-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-client-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-client-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-debuginfo-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-debuginfo-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-debuginfo-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-python-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipa-python-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-python-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-server-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-server-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-server-selinux-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-server-selinux-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipa-server-trust-ad-3.0.0-47.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipa-server-trust-ad-3.0.0-47.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-debuginfo / ipa-python / etc");
  }
}
