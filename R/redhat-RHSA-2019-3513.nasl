#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3513. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130546);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/17");

  script_cve_id("CVE-2016-10739");
  script_xref(name:"RHSA", value:"2019:3513");

  script_name(english:"RHEL 8 : glibc (RHSA-2019:3513)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for glibc is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
name service cache daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

Security Fix(es) :

* glibc: getaddrinfo should reject IP addresses with trailing
characters (CVE-2016-10739)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 8.1 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?774148ae"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:3513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-10739"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-libpthread-nonshared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-benchtests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-agr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-anp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ayc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bhb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bho");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-brx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-byn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-chr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-cmn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-crh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-cv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-doi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-gez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-gv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ik");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-iu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-kl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-kok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-kw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ky");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-li");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ln");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lzh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mfe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mhr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-miq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mjw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nhn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-niu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-os");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-pap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-quz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-raj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-shn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-shs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-so");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tcy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-the");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-to");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-unm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-wa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-wae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-wal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-wo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-yi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-yo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-yue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-yuw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-locale-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-minimal-langpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss_db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss_hesiod");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3513";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"compat-libpthread-nonshared-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"compat-libpthread-nonshared-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"glibc-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-all-langpacks-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-all-langpacks-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"glibc-benchtests-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-benchtests-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-benchtests-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-common-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-common-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"glibc-debuginfo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"glibc-debuginfo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-debuginfo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-debuginfo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"glibc-debuginfo-common-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-debuginfo-common-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-debuginfo-common-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"glibc-devel-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-devel-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-devel-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"glibc-headers-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-headers-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-headers-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-aa-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-aa-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-af-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-af-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-agr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-agr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ak-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ak-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-am-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-am-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-an-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-an-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-anp-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-anp-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ar-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ar-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-as-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-as-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ast-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ast-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ayc-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ayc-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-az-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-az-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-be-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-be-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-bem-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-bem-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ber-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ber-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-bg-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-bg-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-bhb-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-bhb-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-bho-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-bho-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-bi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-bi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-bn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-bn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-bo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-bo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-br-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-br-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-brx-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-brx-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-bs-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-bs-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-byn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-byn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ca-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ca-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ce-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ce-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-chr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-chr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-cmn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-cmn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-crh-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-crh-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-cs-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-cs-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-csb-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-csb-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-cv-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-cv-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-cy-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-cy-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-da-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-da-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-de-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-de-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-doi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-doi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-dsb-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-dsb-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-dv-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-dv-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-dz-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-dz-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-el-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-el-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-en-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-en-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-eo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-eo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-es-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-es-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-et-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-et-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-eu-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-eu-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-fa-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-fa-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ff-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ff-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-fi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-fi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-fil-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-fil-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-fo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-fo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-fr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-fr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-fur-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-fur-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-fy-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-fy-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ga-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ga-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-gd-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-gd-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-gez-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-gez-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-gl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-gl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-gu-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-gu-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-gv-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-gv-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ha-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ha-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-hak-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-hak-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-he-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-he-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-hi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-hi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-hif-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-hif-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-hne-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-hne-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-hr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-hr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-hsb-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-hsb-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ht-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ht-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-hu-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-hu-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-hy-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-hy-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ia-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ia-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-id-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-id-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ig-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ig-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ik-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ik-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-is-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-is-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-it-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-it-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-iu-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-iu-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ja-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ja-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ka-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ka-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-kab-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-kab-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-kk-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-kk-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-kl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-kl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-km-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-km-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-kn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-kn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ko-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ko-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-kok-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-kok-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ks-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ks-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ku-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ku-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-kw-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-kw-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ky-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ky-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-lb-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-lb-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-lg-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-lg-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-li-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-li-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-lij-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-lij-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ln-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ln-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-lo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-lo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-lt-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-lt-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-lv-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-lv-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-lzh-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-lzh-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-mag-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-mag-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-mai-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-mai-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-mfe-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-mfe-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-mg-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-mg-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-mhr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-mhr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-mi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-mi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-miq-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-miq-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-mjw-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-mjw-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-mk-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-mk-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ml-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ml-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-mn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-mn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-mni-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-mni-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-mr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-mr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ms-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ms-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-mt-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-mt-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-my-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-my-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-nan-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-nan-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-nb-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-nb-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-nds-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-nds-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ne-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ne-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-nhn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-nhn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-niu-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-niu-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-nl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-nl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-nn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-nn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-nr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-nr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-nso-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-nso-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-oc-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-oc-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-om-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-om-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-or-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-or-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-os-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-os-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-pa-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-pa-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-pap-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-pap-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-pl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-pl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ps-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ps-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-pt-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-pt-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-quz-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-quz-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-raj-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-raj-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ro-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ro-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ru-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ru-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-rw-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-rw-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sa-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sa-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sah-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sah-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sat-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sat-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sc-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sc-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sd-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sd-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-se-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-se-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sgs-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sgs-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-shn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-shn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-shs-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-shs-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-si-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-si-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sid-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sid-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sk-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sk-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sm-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sm-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-so-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-so-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sq-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sq-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ss-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ss-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-st-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-st-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sv-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sv-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-sw-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-sw-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-szl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-szl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ta-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ta-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-tcy-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-tcy-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-te-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-te-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-tg-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-tg-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-th-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-th-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-the-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-the-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ti-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ti-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-tig-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-tig-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-tk-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-tk-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-tl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-tl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-tn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-tn-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-to-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-to-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-tpi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-tpi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-tr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-tr-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ts-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ts-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-tt-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-tt-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ug-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ug-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-uk-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-uk-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-unm-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-unm-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ur-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ur-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-uz-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-uz-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-ve-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-ve-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-vi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-vi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-wa-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-wa-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-wae-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-wae-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-wal-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-wal-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-wo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-wo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-xh-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-xh-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-yi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-yi-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-yo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-yo-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-yue-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-yue-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-yuw-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-yuw-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-zh-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-zh-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-langpack-zu-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-langpack-zu-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-locale-source-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-locale-source-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-minimal-langpack-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-minimal-langpack-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"glibc-nss-devel-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"glibc-nss-devel-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-nss-devel-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-nss-devel-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"glibc-static-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"glibc-static-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-static-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-static-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"glibc-utils-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"glibc-utils-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libnsl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libnsl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libnsl-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"nscd-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nscd-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"nss_db-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"nss_db-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nss_db-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"nss_hesiod-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"nss_hesiod-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"nss_hesiod-2.28-72.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nss_hesiod-2.28-72.el8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-libpthread-nonshared / glibc / glibc-all-langpacks / etc");
  }
}
