#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2130 and 
# CentOS Errata and Security Advisory 2019:2130 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128358);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-16858");
  script_xref(name:"RHSA", value:"2019:2130");

  script_name(english:"CentOS 7 : libreoffice (CESA-2019:2130)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libreoffice is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

LibreOffice is an open source, community-developed office productivity
suite. It includes key desktop applications, such as a word processor,
a spreadsheet, a presentation manager, a formula editor, and a drawing
program. LibreOffice replaces OpenOffice and provides a similar but
enhanced and extended office suite.

Security Fix(es) :

* libreoffice: Arbitrary python functions in arbitrary modules on the
filesystem can be executed without warning (CVE-2018-16858)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/005961.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0f3ed89"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreoffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16858");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'LibreOffice Macro Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-gdb-debug-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-help-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-nlpsolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-officebean-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-ure-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreofficekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreofficekit-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-af-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-bg-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ca-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-cs-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-da-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-de-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-en-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-es-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-fa-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-fi-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-fr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ga-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-hr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-hu-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-is-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-it-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ja-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ko-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-lb-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-lt-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-mn-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-nl-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-pl-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-pt-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ro-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ru-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-sk-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-sl-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-sr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-sv-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-tr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-vi-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-zh-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-base-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-bsh-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-calc-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-core-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-data-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-draw-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-emailmerge-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-filters-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-gdb-debug-support-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-glade-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-graphicfilter-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-gtk2-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-gtk3-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-ar-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-bg-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-bn-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-ca-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-cs-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-da-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-de-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-dz-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-el-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-es-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-et-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-eu-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-fi-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-fr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-gl-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-gu-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-he-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-hi-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-hr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-hu-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-id-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-it-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-ja-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-ko-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-lt-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-lv-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-nb-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-nl-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-nn-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-pl-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-pt-BR-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-pt-PT-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-ro-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-ru-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-si-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-sk-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-sl-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-sv-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-ta-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-tr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-uk-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-zh-Hans-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-help-zh-Hant-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-impress-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-af-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ar-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-as-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-bg-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-bn-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-br-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ca-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-cs-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-cy-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-da-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-de-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-dz-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-el-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-en-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-es-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-et-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-eu-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-fa-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-fi-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-fr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ga-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-gl-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-gu-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-he-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-hi-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-hr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-hu-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-id-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-it-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ja-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-kk-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-kn-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ko-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-lt-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-lv-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-mai-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ml-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-mr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nb-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nl-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nn-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nso-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-or-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-pa-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-pl-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-pt-BR-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-pt-PT-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ro-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ru-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-si-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-sk-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-sl-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-sr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ss-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-st-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-sv-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ta-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-te-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-th-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-tn-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-tr-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ts-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-uk-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ve-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-xh-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hans-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hant-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-zu-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-librelogo-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-math-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-nlpsolver-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-officebean-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-officebean-common-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-ogltrans-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-opensymbol-fonts-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-pdfimport-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-postgresql-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-pyuno-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-rhino-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-sdk-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-sdk-doc-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-ure-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-ure-common-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-wiki-publisher-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-writer-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-x11-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-xsltfilter-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreofficekit-5.3.6.1-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreofficekit-devel-5.3.6.1-21.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autocorr-af / autocorr-bg / autocorr-ca / autocorr-cs / autocorr-da / etc");
}
