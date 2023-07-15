#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4602. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132875);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-12207", "CVE-2019-11091", "CVE-2019-11135", "CVE-2019-17340", "CVE-2019-17341", "CVE-2019-17342", "CVE-2019-17343", "CVE-2019-17344", "CVE-2019-17345", "CVE-2019-17346", "CVE-2019-17347", "CVE-2019-17348", "CVE-2019-17349", "CVE-2019-17350", "CVE-2019-18420", "CVE-2019-18421", "CVE-2019-18422", "CVE-2019-18423", "CVE-2019-18424", "CVE-2019-18425", "CVE-2019-19577", "CVE-2019-19578", "CVE-2019-19579", "CVE-2019-19580", "CVE-2019-19581", "CVE-2019-19582", "CVE-2019-19583");
  script_xref(name:"DSA", value:"4602");
  script_xref(name:"IAVB", value:"2019-B-0091-S");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"Debian DSA-4602-1 : xen - security update (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor,
which could result in denial of service, guest-to-host privilege
escalation or information leaks.

In addition this update provides mitigations for the 'TSX Asynchronous
Abort'speculative side channel attack. For additional information
please refer to https://xenbits.xen.org/xsa/advisory-305.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://xenbits.xen.org/xsa/advisory-305.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4602"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the xen packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 4.8.5.final+shim4.10.4-1+deb9u12. Note that this will
be the last security update for Xen in the oldstable distribution;
upstream support for the 4.8.x branch ended by the end of December
2019. If you rely on security support for your Xen installation an
update to the stable distribution (buster) is recommended.

For the stable distribution (buster), these problems have been fixed
in version 4.11.3+24-g14b62ab3e5-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libxen-dev", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libxencall1", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libxendevicemodel1", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libxenevtchn1", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libxenforeignmemory1", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libxengnttab1", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libxenmisc4.11", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libxenstore3.0", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libxentoolcore1", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libxentoollog1", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xen-doc", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xen-hypervisor-4.11-amd64", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xen-hypervisor-4.11-arm64", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xen-hypervisor-4.11-armhf", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xen-hypervisor-common", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xen-system-amd64", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xen-system-arm64", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xen-system-armhf", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xen-utils-4.11", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xen-utils-common", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xenstore-utils", reference:"4.11.3+24-g14b62ab3e5-1~deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxen-4.8", reference:"4.8.5.final+shim4.10.4-1+deb9u12")) flag++;
if (deb_check(release:"9.0", prefix:"libxen-dev", reference:"4.8.5.final+shim4.10.4-1+deb9u12")) flag++;
if (deb_check(release:"9.0", prefix:"libxenstore3.0", reference:"4.8.5.final+shim4.10.4-1+deb9u12")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-amd64", reference:"4.8.5.final+shim4.10.4-1+deb9u12")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-arm64", reference:"4.8.5.final+shim4.10.4-1+deb9u12")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-armhf", reference:"4.8.5.final+shim4.10.4-1+deb9u12")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-amd64", reference:"4.8.5.final+shim4.10.4-1+deb9u12")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-arm64", reference:"4.8.5.final+shim4.10.4-1+deb9u12")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-armhf", reference:"4.8.5.final+shim4.10.4-1+deb9u12")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-4.8", reference:"4.8.5.final+shim4.10.4-1+deb9u12")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-common", reference:"4.8.5.final+shim4.10.4-1+deb9u12")) flag++;
if (deb_check(release:"9.0", prefix:"xenstore-utils", reference:"4.8.5.final+shim4.10.4-1+deb9u12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
