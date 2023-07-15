#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1131.
#

include("compat.inc");

if (description)
{
  script_id(119785);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2018-11237");
  script_xref(name:"ALAS", value:"2018-1131");

  script_name(english:"Amazon Linux 2 : glibc (ALAS-2018-1131)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow has been discovered in the GNU C Library (aka glibc
or libc6) in the __mempcpy_avx512_no_vzeroupper function when
particular conditions are met. An attacker could use this
vulnerability to cause a denial of service or potentially execute
code.(CVE-2018-11237)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1131.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update glibc' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-benchtests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-anp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ayc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-bem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-bhb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-bho");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-bo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-brx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-byn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-chr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-cmn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-crh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-cv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-doi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-fil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-fo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-fur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-gez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-gv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-hak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-hne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ik");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-iu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-kl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-kok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-kw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ky");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-li");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ln");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-lo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-lzh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-mag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-mg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-mhr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-mi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-mni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-mt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-nan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-nds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-nhn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-niu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-os");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-pap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-quz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-raj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-sa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-sat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-sc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-sgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-shs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-sid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-so");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-sw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-tcy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-the");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-tig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-tt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-unm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-wa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-wae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-wal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-wo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-yi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-yo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-yue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-locale-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-minimal-langpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcrypt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss_db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss_hesiod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss_nis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"glibc-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-all-langpacks-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-benchtests-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-common-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-debuginfo-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-debuginfo-common-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-devel-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-headers-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-aa-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-af-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ak-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-am-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-an-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-anp-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ar-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-as-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ast-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ayc-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-az-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-be-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-bem-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ber-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-bg-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-bhb-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-bho-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-bn-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-bo-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-br-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-brx-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-bs-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-byn-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ca-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ce-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-chr-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-cmn-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-crh-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-cs-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-csb-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-cv-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-cy-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-da-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-de-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-doi-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-dv-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-dz-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-el-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-en-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-eo-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-es-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-et-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-eu-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-fa-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ff-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-fi-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-fil-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-fo-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-fr-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-fur-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-fy-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ga-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-gd-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-gez-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-gl-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-gu-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-gv-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ha-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-hak-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-he-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-hi-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-hne-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-hr-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-hsb-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ht-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-hu-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-hy-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ia-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-id-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ig-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ik-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-is-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-it-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-iu-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ja-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ka-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-kk-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-kl-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-km-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-kn-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ko-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-kok-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ks-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ku-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-kw-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ky-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-lb-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-lg-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-li-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-lij-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ln-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-lo-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-lt-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-lv-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-lzh-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-mag-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-mai-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-mg-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-mhr-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-mi-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-mk-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ml-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-mn-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-mni-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-mr-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ms-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-mt-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-my-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-nan-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-nb-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-nds-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ne-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-nhn-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-niu-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-nl-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-nn-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-nr-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-nso-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-oc-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-om-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-or-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-os-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-pa-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-pap-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-pl-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ps-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-pt-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-quz-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-raj-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ro-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ru-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-rw-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-sa-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-sat-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-sc-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-sd-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-se-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-sgs-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-shs-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-si-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-sid-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-sk-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-sl-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-so-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-sq-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-sr-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ss-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-st-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-sv-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-sw-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-szl-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ta-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-tcy-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-te-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-tg-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-th-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-the-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ti-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-tig-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-tk-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-tl-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-tn-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-tr-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ts-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-tt-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ug-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-uk-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-unm-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ur-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-uz-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-ve-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-vi-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-wa-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-wae-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-wal-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-wo-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-xh-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-yi-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-yo-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-yue-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-zh-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-langpack-zu-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-locale-source-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-minimal-langpack-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-nss-devel-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-static-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"glibc-utils-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"libcrypt-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"libcrypt-nss-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"nscd-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"nss_db-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"nss_hesiod-2.26-30.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"nss_nis-2.26-30.amzn2.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-all-langpacks / glibc-benchtests / glibc-common / etc");
}
