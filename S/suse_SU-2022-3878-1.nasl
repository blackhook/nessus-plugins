#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3878-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(177784);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id("CVE-2022-31255", "CVE-2022-43753", "CVE-2022-43754");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3878-1");

  script_name(english:"SUSE SLES15 Security Update : SUSE Manager Server 4.2 (SUSE-SU-2022:3878-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:3878-1 advisory.

  - An Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in
    spacewalk/Uyuni of SUSE Linux Enterprise Module for SUSE Manager Server 4.2, SUSE Linux Enterprise Module
    for SUSE Manager Server 4.3, SUSE Manager Server 4.2 allows remote attackers to read files available to
    the user running the process, typically tomcat. This issue affects: SUSE Linux Enterprise Module for SUSE
    Manager Server 4.2 hub-xmlrpc-api-0.7-150300.3.9.2, inter-server-sync-0.2.4-150300.8.25.2, locale-
    formula-0.3-150300.3.3.2, py27-compat-salt-3000.3-150300.7.7.26.2, python-
    urlgrabber-3.10.2.1py2_3-150300.3.3.2, spacecmd-4.2.20-150300.4.30.2, spacewalk-
    backend-4.2.25-150300.4.32.4, spacewalk-client-tools-4.2.21-150300.4.27.3, spacewalk-
    java-4.2.43-150300.3.48.2, spacewalk-utils-4.2.18-150300.3.21.2, spacewalk-web-4.2.30-150300.3.30.3,
    susemanager-4.2.38-150300.3.44.3, susemanager-doc-indexes-4.2-150300.12.36.3, susemanager-
    docs_en-4.2-150300.12.36.2, susemanager-schema-4.2.25-150300.3.30.3, susemanager-sls versions prior to
    4.2.28. SUSE Linux Enterprise Module for SUSE Manager Server 4.3 spacewalk-java versions prior to 4.3.39.
    SUSE Manager Server 4.2 release-notes-susemanager versions prior to 4.2.10. (CVE-2022-31255)

  - A Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in
    spacewalk/Uyuni of SUSE Linux Enterprise Module for SUSE Manager Server 4.2, SUSE Linux Enterprise Module
    for SUSE Manager Server 4.3, SUSE Manager Server 4.2 allows remote attackers to read files available to
    the user running the process, typically tomcat. This issue affects: SUSE Linux Enterprise Module for SUSE
    Manager Server 4.2 hub-xmlrpc-api-0.7-150300.3.9.2, inter-server-sync-0.2.4-150300.8.25.2, locale-
    formula-0.3-150300.3.3.2, py27-compat-salt-3000.3-150300.7.7.26.2, python-
    urlgrabber-3.10.2.1py2_3-150300.3.3.2, spacecmd-4.2.20-150300.4.30.2, spacewalk-
    backend-4.2.25-150300.4.32.4, spacewalk-client-tools-4.2.21-150300.4.27.3, spacewalk-
    java-4.2.43-150300.3.48.2, spacewalk-utils-4.2.18-150300.3.21.2, spacewalk-web-4.2.30-150300.3.30.3,
    susemanager-4.2.38-150300.3.44.3, susemanager-doc-indexes-4.2-150300.12.36.3, susemanager-
    docs_en-4.2-150300.12.36.2, susemanager-schema-4.2.25-150300.3.30.3, susemanager-sls versions prior to
    4.2.28. SUSE Linux Enterprise Module for SUSE Manager Server 4.3 spacewalk-java versions prior to 4.3.39.
    SUSE Manager Server 4.2 release-notes-susemanager versions prior to 4.2.10. (CVE-2022-43753)

  - An Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in
    spacewalk/Uyuni of SUSE Linux Enterprise Module for SUSE Manager Server 4.2, SUSE Linux Enterprise Module
    for SUSE Manager Server 4.3, SUSE Manager Server 4.2 allows remote attackers to embed Javascript code via
    /rhn/audit/scap/Search.do This issue affects: SUSE Linux Enterprise Module for SUSE Manager Server 4.2
    hub-xmlrpc-api-0.7-150300.3.9.2, inter-server-sync-0.2.4-150300.8.25.2, locale-formula-0.3-150300.3.3.2,
    py27-compat-salt-3000.3-150300.7.7.26.2, python-urlgrabber-3.10.2.1py2_3-150300.3.3.2,
    spacecmd-4.2.20-150300.4.30.2, spacewalk-backend-4.2.25-150300.4.32.4, spacewalk-client-
    tools-4.2.21-150300.4.27.3, spacewalk-java-4.2.43-150300.3.48.2, spacewalk-utils-4.2.18-150300.3.21.2,
    spacewalk-web-4.2.30-150300.3.30.3, susemanager-4.2.38-150300.3.44.3, susemanager-doc-
    indexes-4.2-150300.12.36.3, susemanager-docs_en-4.2-150300.12.36.2, susemanager-
    schema-4.2.25-150300.3.30.3, susemanager-sls versions prior to 4.2.28. SUSE Linux Enterprise Module for
    SUSE Manager Server 4.3 spacewalk-java versions prior to 4.3.39. SUSE Manager Server 4.2 release-notes-
    susemanager versions prior to 4.2.10. (CVE-2022-43754)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204741");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-November/012815.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab844c47");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31255");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-43753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-43754");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-43754");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hub-xmlrpc-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:inter-server-sync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:locale-formula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:py27-compat-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-urlgrabber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacecmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-config-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-config-files-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-config-files-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-iss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-iss-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-package-push-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-xml-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-base-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-base-minimal-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-java-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-utils-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-doc-indexes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-docs_en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-docs_en-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-sls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uyuni-config-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'hub-xmlrpc-api-0.7-150300.3.9.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'inter-server-sync-0.2.4-150300.8.25.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'locale-formula-0.3-150300.3.3.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'py27-compat-salt-3000.3-150300.7.7.26.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'python3-spacewalk-client-tools-4.2.21-150300.4.27.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'python3-urlgrabber-3.10.2.1py2_3-150300.3.3.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacecmd-4.2.20-150300.4.30.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-app-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-applet-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-config-files-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-config-files-common-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-config-files-tool-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-iss-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-iss-export-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-package-push-server-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-server-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-sql-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-sql-postgresql-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-tools-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-xml-export-libs-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-backend-xmlrpc-4.2.25-150300.4.32.4', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-base-4.2.30-150300.3.30.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-base-minimal-4.2.30-150300.3.30.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-base-minimal-config-4.2.30-150300.3.30.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-client-tools-4.2.21-150300.4.27.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-html-4.2.30-150300.3.30.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-java-4.2.43-150300.3.48.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-java-config-4.2.43-150300.3.48.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-java-lib-4.2.43-150300.3.48.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-java-postgresql-4.2.43-150300.3.48.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-taskomatic-4.2.43-150300.3.48.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-utils-4.2.18-150300.3.21.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'spacewalk-utils-extras-4.2.18-150300.3.21.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'susemanager-4.2.38-150300.3.44.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'susemanager-doc-indexes-4.2-150300.12.36.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'susemanager-docs_en-4.2-150300.12.36.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'susemanager-docs_en-pdf-4.2-150300.12.36.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'susemanager-schema-4.2.25-150300.3.30.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'susemanager-sls-4.2.28-150300.3.36.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'susemanager-tools-4.2.38-150300.3.44.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'uyuni-config-modules-4.2.28-150300.3.36.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hub-xmlrpc-api / inter-server-sync / locale-formula / etc');
}
