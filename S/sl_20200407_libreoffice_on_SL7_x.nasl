#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(135817);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2019-9848", "CVE-2019-9849", "CVE-2019-9850", "CVE-2019-9851", "CVE-2019-9852", "CVE-2019-9853", "CVE-2019-9854");

  script_name(english:"Scientific Linux Security Update : libreoffice on SL7.x x86_64 (20200407)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"* libreoffice: LibreLogo script can be manipulated into executing
arbitrary python commands * libreoffice: Insufficient URL validation
allowing LibreLogo script execution * libreoffice: LibreLogo
global-event script execution * libreoffice: Insufficient URL encoding
flaw in allowed script location check * libreoffice: Insufficient URL
decoding flaw in categorizing macro location * libreoffice: Unsafe URL
assembly flaw in allowed script location check * libreoffice: Remote
resources protection module not applied to bullet graphics"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2004&L=SCIENTIFIC-LINUX-ERRATA&P=15929
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1837df17"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'LibreOffice Macro Python Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-gdb-debug-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-help-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-nlpsolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-officebean-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-ure-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreofficekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreofficekit-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", reference:"autocorr-af-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-bg-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ca-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-cs-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-da-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-de-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-en-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-es-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-fa-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-fi-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-fr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ga-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-hr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-hu-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-is-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-it-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ja-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ko-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-lb-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-lt-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-mn-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-nl-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-pl-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-pt-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ro-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ru-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-sk-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-sl-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-sr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-sv-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-tr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-vi-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-zh-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-base-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-bsh-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-calc-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-core-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libreoffice-data-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-debuginfo-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-draw-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-emailmerge-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-filters-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-gdb-debug-support-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-glade-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-graphicfilter-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-gtk2-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-gtk3-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-ar-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-bg-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-bn-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-ca-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-cs-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-da-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-de-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-dz-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-el-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-es-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-et-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-eu-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-fi-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-fr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-gl-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-gu-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-he-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-hi-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-hr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-hu-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-id-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-it-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-ja-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-ko-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-lt-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-lv-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-nb-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-nl-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-nn-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-pl-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-pt-BR-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-pt-PT-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-ro-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-ru-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-si-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-sk-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-sl-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-sv-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-ta-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-tr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-uk-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-zh-Hans-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-help-zh-Hant-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-impress-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-af-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ar-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-as-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-bg-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-bn-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-br-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ca-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-cs-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-cy-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-da-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-de-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-dz-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-el-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-en-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-es-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-et-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-eu-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-fa-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-fi-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-fr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ga-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-gl-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-gu-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-he-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-hi-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-hr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-hu-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-id-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-it-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ja-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-kk-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-kn-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ko-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-lt-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-lv-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-mai-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ml-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-mr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nb-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nl-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nn-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nso-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-or-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-pa-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-pl-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-pt-BR-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-pt-PT-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ro-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ru-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-si-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-sk-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-sl-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-sr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ss-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-st-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-sv-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ta-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-te-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-th-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-tn-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-tr-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ts-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-uk-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ve-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-xh-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hans-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hant-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-zu-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-librelogo-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-math-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-nlpsolver-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-officebean-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libreoffice-officebean-common-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-ogltrans-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libreoffice-opensymbol-fonts-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-pdfimport-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-postgresql-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-pyuno-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-rhino-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-sdk-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-sdk-doc-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-ure-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libreoffice-ure-common-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-wiki-publisher-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-writer-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-x11-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-xsltfilter-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreofficekit-5.3.6.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreofficekit-devel-5.3.6.1-24.el7")) flag++;


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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autocorr-af / autocorr-bg / autocorr-ca / autocorr-cs / autocorr-da / etc");
}
