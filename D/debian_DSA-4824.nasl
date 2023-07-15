#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4824. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144672);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2020-15959", "CVE-2020-15960", "CVE-2020-15961", "CVE-2020-15962", "CVE-2020-15963", "CVE-2020-15964", "CVE-2020-15965", "CVE-2020-15966", "CVE-2020-15967", "CVE-2020-15968", "CVE-2020-15969", "CVE-2020-15970", "CVE-2020-15971", "CVE-2020-15972", "CVE-2020-15973", "CVE-2020-15974", "CVE-2020-15975", "CVE-2020-15976", "CVE-2020-15977", "CVE-2020-15978", "CVE-2020-15979", "CVE-2020-15980", "CVE-2020-15981", "CVE-2020-15982", "CVE-2020-15983", "CVE-2020-15984", "CVE-2020-15985", "CVE-2020-15986", "CVE-2020-15987", "CVE-2020-15988", "CVE-2020-15989", "CVE-2020-15990", "CVE-2020-15991", "CVE-2020-15992", "CVE-2020-15999", "CVE-2020-16000", "CVE-2020-16001", "CVE-2020-16002", "CVE-2020-16003", "CVE-2020-16004", "CVE-2020-16005", "CVE-2020-16006", "CVE-2020-16007", "CVE-2020-16008", "CVE-2020-16009", "CVE-2020-16011", "CVE-2020-16012", "CVE-2020-16013", "CVE-2020-16014", "CVE-2020-16015", "CVE-2020-16016", "CVE-2020-16017", "CVE-2020-16018", "CVE-2020-16019", "CVE-2020-16020", "CVE-2020-16021", "CVE-2020-16022", "CVE-2020-16023", "CVE-2020-16024", "CVE-2020-16025", "CVE-2020-16026", "CVE-2020-16027", "CVE-2020-16028", "CVE-2020-16029", "CVE-2020-16030", "CVE-2020-16031", "CVE-2020-16032", "CVE-2020-16033", "CVE-2020-16034", "CVE-2020-16035", "CVE-2020-16036", "CVE-2020-16037", "CVE-2020-16038", "CVE-2020-16039", "CVE-2020-16040", "CVE-2020-16041", "CVE-2020-16042", "CVE-2020-6510", "CVE-2020-6511", "CVE-2020-6512", "CVE-2020-6513", "CVE-2020-6514", "CVE-2020-6515", "CVE-2020-6516", "CVE-2020-6517", "CVE-2020-6518", "CVE-2020-6519", "CVE-2020-6520", "CVE-2020-6521", "CVE-2020-6522", "CVE-2020-6523", "CVE-2020-6524", "CVE-2020-6525", "CVE-2020-6526", "CVE-2020-6527", "CVE-2020-6528", "CVE-2020-6529", "CVE-2020-6530", "CVE-2020-6531", "CVE-2020-6532", "CVE-2020-6533", "CVE-2020-6534", "CVE-2020-6535", "CVE-2020-6536", "CVE-2020-6537", "CVE-2020-6538", "CVE-2020-6539", "CVE-2020-6540", "CVE-2020-6541", "CVE-2020-6542", "CVE-2020-6543", "CVE-2020-6544", "CVE-2020-6545", "CVE-2020-6546", "CVE-2020-6547", "CVE-2020-6548", "CVE-2020-6549", "CVE-2020-6550", "CVE-2020-6551", "CVE-2020-6552", "CVE-2020-6553", "CVE-2020-6554", "CVE-2020-6555", "CVE-2020-6556", "CVE-2020-6557", "CVE-2020-6558", "CVE-2020-6559", "CVE-2020-6560", "CVE-2020-6561", "CVE-2020-6562", "CVE-2020-6563", "CVE-2020-6564", "CVE-2020-6565", "CVE-2020-6566", "CVE-2020-6567", "CVE-2020-6568", "CVE-2020-6569", "CVE-2020-6570", "CVE-2020-6571", "CVE-2020-6573", "CVE-2020-6574", "CVE-2020-6575", "CVE-2020-6576");
  script_xref(name:"DSA", value:"4824");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0124");

  script_name(english:"Debian DSA-4824-1 : chromium - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues were discovered in the Chromium web browser,
which could result in the execution of arbitrary code, denial of
service or information disclosure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4824"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the chromium packages.

For the stable distribution (buster), these problems have been fixed
in version 87.0.4280.88-0.4~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6559");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome versions before 87.0.4280.88 integer overflow during SimplfiedLowering phase');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"10.0", prefix:"chromium", reference:"87.0.4280.88-0.4~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-common", reference:"87.0.4280.88-0.4~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-driver", reference:"87.0.4280.88-0.4~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-l10n", reference:"87.0.4280.88-0.4~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-sandbox", reference:"87.0.4280.88-0.4~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-shell", reference:"87.0.4280.88-0.4~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
