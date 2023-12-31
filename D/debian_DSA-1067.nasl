#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1067. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22609);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2003-0984", "CVE-2004-0138", "CVE-2004-0394", "CVE-2004-0427", "CVE-2004-0447", "CVE-2004-0554", "CVE-2004-0565", "CVE-2004-0685", "CVE-2004-0883", "CVE-2004-0949", "CVE-2004-0997", "CVE-2004-1016", "CVE-2004-1017", "CVE-2004-1068", "CVE-2004-1070", "CVE-2004-1071", "CVE-2004-1072", "CVE-2004-1073", "CVE-2004-1074", "CVE-2004-1234", "CVE-2004-1235", "CVE-2004-1333", "CVE-2004-1335", "CVE-2005-0001", "CVE-2005-0003", "CVE-2005-0124", "CVE-2005-0135", "CVE-2005-0384", "CVE-2005-0489", "CVE-2005-0504");
  script_xref(name:"DSA", value:"1067");

  script_name(english:"Debian DSA-1067-1 : kernel-source-2.4.16 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local and remote vulnerabilities have been discovered in the
Linux kernel that may lead to a denial of service or the execution of
arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2004-0427
    A local denial of service vulnerability in do_fork() has
    been found.

  - CVE-2005-0489
    A local denial of service vulnerability in proc memory
    handling has been found.

  - CVE-2004-0394
    A buffer overflow in the panic handling code has been
    found.

  - CVE-2004-0447
    A local denial of service vulnerability through a NULL
    pointer dereference in the IA64 process handling code
    has been found.

  - CVE-2004-0554
    A local denial of service vulnerability through an
    infinite loop in the signal handler code has been found.

  - CVE-2004-0565
    An information leak in the context switch code has been
    found on the IA64 architecture.

  - CVE-2004-0685
    Unsafe use of copy_to_user in USB drivers may disclose
    sensitive information.

  - CVE-2005-0001
    A race condition in the i386 page fault handler may
    allow privilege escalation.

  - CVE-2004-0883
    Multiple vulnerabilities in the SMB filesystem code may
    allow denial of service or information disclosure.

  - CVE-2004-0949
    An information leak discovered in the SMB filesystem
    code.

  - CVE-2004-1016
    A local denial of service vulnerability has been found
    in the SCM layer.

  - CVE-2004-1333
    An integer overflow in the terminal code may allow a
    local denial of service vulnerability.

  - CVE-2004-0997
    A local privilege escalation in the MIPS assembly code
    has been found.

  - CVE-2004-1335
    A memory leak in the ip_options_get() function may lead
    to denial of service.

  - CVE-2004-1017
    Multiple overflows exist in the io_edgeport driver which
    might be usable as a denial of service attack vector.

  - CVE-2005-0124
    Bryan Fulton reported a bounds checking bug in the
    coda_pioctl function which may allow local users to
    execute arbitrary code or trigger a denial of service
    attack.

  - CVE-2003-0984
    Inproper initialization of the RTC may disclose
    information.

  - CVE-2004-1070
    Insufficient input sanitising in the load_elf_binary()
    function may lead to privilege escalation.

  - CVE-2004-1071
    Incorrect error handling in the binfmt_elf loader may
    lead to privilege escalation.

  - CVE-2004-1072
    A buffer overflow in the binfmt_elf loader may lead to
    privilege escalation or denial of service.

  - CVE-2004-1073
    The open_exec function may disclose information.

  - CVE-2004-1074
    The binfmt code is vulnerable to denial of service
    through malformed a.out binaries.

  - CVE-2004-0138
    A denial of service vulnerability in the ELF loader has
    been found.

  - CVE-2004-1068
    A programming error in the unix_dgram_recvmsg() function
    may lead to privilege escalation.

  - CVE-2004-1234
    The ELF loader is vulnerable to denial of service
    through malformed binaries.

  - CVE-2005-0003
    Crafted ELF binaries may lead to privilege escalation,
    due to insufficient checking of overlapping memory
    regions.

  - CVE-2004-1235
    A race condition in the load_elf_library() and
    binfmt_aout() functions may allow privilege escalation.

  - CVE-2005-0504
    An integer overflow in the Moxa driver may lead to
    privilege escalation.

  - CVE-2005-0384
    A remote denial of service vulnerability has been found
    in the PPP driver.

  - CVE-2005-0135
    An IA64 specific local denial of service vulnerability
    has been found in the unw_unwind_to_user() function.

The following matrix explains which kernel version for which
architecture fixes the problems mentioned above :

                               Debian 3.0 (woody)           
  Source                       2.4.16-1woody2               
  arm/lart                     20040419woody1               
  arm/netwinder                20040419woody1               
  arm/riscpc                   20040419woody1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-0427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-0489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-0394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-0447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-0554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-0565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-0685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-0001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-0883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-0949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-0997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-0124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2003-0984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-0138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-0003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-0504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-0384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-0135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1067"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the kernel package immediately and reboot the machine."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.16-lart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.16-netwinder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.16-riscpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.4.16");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"kernel-doc-2.4.16", reference:"2.4.16-1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.16", reference:"20040419woody1")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.16-lart", reference:"20040419woody1")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.16-netwinder", reference:"20040419woody1")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.16-riscpc", reference:"20040419woody1")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-source-2.4.16", reference:"2.4.16-1woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
