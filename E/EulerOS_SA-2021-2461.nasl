#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153642);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-35942");

  script_name(english:"EulerOS 2.0 SP8 : glibc (EulerOS-SA-2021-2461)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - The wordexp function in the GNU C Library (aka glibc) through 2.33 may crash or read arbitrary memory in
    parse_param (in posix/wordexp.c) when called with an untrusted, crafted pattern, potentially resulting in
    a denial of service or disclosure of information. This occurs because atoi was used but strtoul should
    have been used to ensure correct calculations. (CVE-2021-35942)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2461
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e492d713");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35942");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-agr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-anp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ayc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-bem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-bhb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-bho");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-bi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-bo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-brx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-byn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-chr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-cmn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-crh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-cv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-doi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-fil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-fo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-fur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-gez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-gv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-hak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-hif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-hne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ik");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-iu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-kl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-kok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-kw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ky");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-li");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ln");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-lo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-lzh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-mag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-mfe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-mg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-mhr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-mi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-miq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-mjw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-mni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-mt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-nan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-nds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-nhn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-niu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-os");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-pap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-quz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-raj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-shn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-shs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-so");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-sw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-tcy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-the");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-tig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-to");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-tpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-tt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-unm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-wa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-wae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-wal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-wo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-yi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-yo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-yue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-yuw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-locale-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-minimal-langpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss_db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss_hesiod");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "glibc-2.28-9.h64.eulerosv2r8",
  "glibc-all-langpacks-2.28-9.h64.eulerosv2r8",
  "glibc-common-2.28-9.h64.eulerosv2r8",
  "glibc-devel-2.28-9.h64.eulerosv2r8",
  "glibc-headers-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-aa-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-af-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-agr-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ak-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-am-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-an-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-anp-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ar-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-as-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ast-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ayc-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-az-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-be-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-bem-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ber-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-bg-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-bhb-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-bho-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-bi-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-bn-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-bo-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-br-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-brx-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-bs-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-byn-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ca-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ce-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-chr-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-cmn-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-crh-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-cs-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-csb-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-cv-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-cy-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-da-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-de-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-doi-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-dsb-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-dv-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-dz-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-el-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-en-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-eo-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-es-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-et-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-eu-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-fa-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ff-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-fi-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-fil-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-fo-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-fr-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-fur-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-fy-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ga-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-gd-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-gez-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-gl-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-gu-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-gv-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ha-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-hak-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-he-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-hi-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-hif-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-hne-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-hr-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-hsb-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ht-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-hu-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-hy-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ia-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-id-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ig-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ik-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-is-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-it-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-iu-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ja-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ka-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-kab-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-kk-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-kl-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-km-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-kn-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ko-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-kok-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ks-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ku-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-kw-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ky-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-lb-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-lg-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-li-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-lij-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ln-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-lo-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-lt-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-lv-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-lzh-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-mag-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-mai-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-mfe-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-mg-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-mhr-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-mi-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-miq-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-mjw-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-mk-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ml-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-mn-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-mni-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-mr-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ms-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-mt-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-my-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-nan-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-nb-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-nds-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ne-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-nhn-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-niu-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-nl-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-nn-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-nr-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-nso-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-oc-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-om-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-or-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-os-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-pa-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-pap-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-pl-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ps-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-pt-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-quz-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-raj-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ro-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ru-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-rw-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sa-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sah-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sat-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sc-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sd-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-se-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sgs-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-shn-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-shs-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-si-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sid-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sk-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sl-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sm-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-so-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sq-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sr-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ss-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-st-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sv-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-sw-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-szl-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ta-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-tcy-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-te-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-tg-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-th-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-the-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ti-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-tig-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-tk-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-tl-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-tn-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-to-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-tpi-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-tr-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ts-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-tt-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ug-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-uk-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-unm-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ur-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-uz-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-ve-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-vi-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-wa-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-wae-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-wal-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-wo-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-xh-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-yi-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-yo-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-yue-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-yuw-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-zh-2.28-9.h64.eulerosv2r8",
  "glibc-langpack-zu-2.28-9.h64.eulerosv2r8",
  "glibc-locale-source-2.28-9.h64.eulerosv2r8",
  "glibc-minimal-langpack-2.28-9.h64.eulerosv2r8",
  "glibc-static-2.28-9.h64.eulerosv2r8",
  "glibc-utils-2.28-9.h64.eulerosv2r8",
  "libnsl-2.28-9.h64.eulerosv2r8",
  "nscd-2.28-9.h64.eulerosv2r8",
  "nss_db-2.28-9.h64.eulerosv2r8",
  "nss_hesiod-2.28-9.h64.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
