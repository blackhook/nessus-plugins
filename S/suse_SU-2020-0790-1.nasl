#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0790-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(134937);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/30");

  script_cve_id("CVE-2018-10903");

  script_name(english:"SUSE SLES12 Security Update : python-cffi, python-cryptography, python-xattr (SUSE-SU-2020:0790-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python-cffi, python-cryptography and python-xattr
fixes the following issues :

Security issue fixed :

CVE-2018-10903: Fixed GCM tag forgery via truncated tag in
finalize_with_tag API (bsc#1101820).

Non-security issues fixed :

python-cffi was updated to 1.11.2 (bsc#1138748, jsc#ECO-1256,
jsc#PM-1598): fixed a build failure on i586 (bsc#1111657)

Salt was unable to highstate in snapshot 20171129 (bsc#1070737)

Update pytest in spec to add c directory tests in addition to testing
directory.

Update to 1.11.1: Fix tests, remove deprecated C API usage

Fix (hack) for 3.6.0/3.6.1/3.6.2 giving incompatible binary extensions
(cpython issue #29943)

Fix for 3.7.0a1+

Update to 1.11.0: Support the modern standard types char16_t and
char32_t. These work like wchar_t: they represent one unicode
character, or when used as charN_t * or charN_t[] they represent a
unicode string. The difference with wchar_t is that they have a known,
fixed size. They should work at all places that used to work with
wchar_t (please report an issue if I missed something). Note that with
set_source(), you need to make sure that these types are actually
defined by the C source you provide (if used in cdef()).

Support the C99 types float _Complex and double _Complex. Note that
libffi doesn't support them, which means that in the ABI mode you
still cannot call C functions that take complex numbers directly as
arguments or return type.

Fixed a rare race condition when creating multiple FFI instances from
multiple threads. (Note that you aren't meant to create many FFI
instances: in inline mode, you should write ffi = cffi.FFI() at module
level just after import cffi; and in out-of-line mode you don't
instantiate FFI explicitly at all.)

Windows: using callbacks can be messy because the CFFI internal error
messages show up to stderr-but stderr goes nowhere in many
applications. This makes it particularly hard to get started with the
embedding mode. (Once you get started, you can at least use
@ffi.def_extern(onerror=...) and send the error logs where it makes
sense for your application, or record them in log files, and so on.)
So what is new in CFFI is that now, on Windows CFFI will try to open a
non-modal MessageBox (in addition to sending raw messages to stderr).
The MessageBox is only visible if the process stays alive: typically,
console applications that crash close immediately, but that is also
the situation where stderr should be visible anyway.

Progress on support for callbacks in NetBSD.

Functions returning booleans would in some case still return 0 or 1
instead of False or True. Fixed.

ffi.gc() now takes an optional third parameter, which gives an
estimate of the size (in bytes) of the object. So far, this is only
used by PyPy, to make the next GC occur more quickly (issue #320). In
the future, this might have an effect on CPython too (provided the
CPython issue 31105 is addressed).

Add a note to the documentation: the ABI mode gives function objects
that are slower to call than the API mode does. For some reason it is
often thought to be faster. It is not!

Update to 1.10.1: Fixed the line numbers reported in case of cdef()
errors. Also, I just noticed, but pycparser always supported the
preprocessor directive # 42 'foo.h' to mean 'from the next line, we're
in file foo.h starting from line 42';, which it puts in the error
messages.

Update to 1.10.0 :

Issue #295: use calloc() directly instead of
PyObject_Malloc()+memset() to handle ffi.new() with a default
allocator. Speeds up ffi.new(large-array) where most of the time you
never touch most of the array. Some OS/X build fixes ('only with Xcode
but without CLT';).

Improve a couple of error messages: when getting mismatched versions
of cffi and its backend; and when calling functions which cannot be
called with libffi because an argument is a struct that is 'too
complicated'; (and not a struct pointer, which always works).

Add support for some unusual compilers (non-msvc, non-gcc, non-icc,
non-clang)

Implemented the remaining cases for ffi.from_buffer. Now all
buffer/memoryview objects can be passed. The one remaining check is
against passing unicode strings in Python 2. (They support the buffer
interface, but that gives the raw bytes behind the UTF16/UCS4 storage,
which is most of the times not what you expect. In Python 3 this has
been fixed and the unicode strings don't support the memoryview
interface any more.)

The C type _Bool or bool now converts to a Python boolean when
reading, instead of the content of the byte as an integer. The
potential incompatibility here is what occurs if the byte contains a
value different from 0 and 1. Previously, it would just return it;
with this change, CFFI raises an exception in this case. But this case
means 'undefined behavior'; in C; if you really have to interface with
a library relying on this, don't use bool in the CFFI side. Also, it
is still valid to use a byte string as initializer for a bool[], but
now it must only contain \x00 or \x01. As an aside, ffi.string() no
longer works on bool[] (but it never made much sense, as this function
stops at the first zero).

ffi.buffer is now the name of cffi's buffer type, and ffi.buffer()
works like before but is the constructor of that type.

ffi.addressof(lib, 'name') now works also in in-line mode, not only in
out-of-line mode. This is useful for taking the address of global
variables.

Issue #255: cdata objects of a primitive type (integers, floats, char)
are now compared and ordered by value. For example, <cdata> compares
equal to 42 and <cdata b> compares equal to b'A'. Unlike C, <cdata>
does not compare equal to ffi.cast('unsigned int', -1): it compares
smaller, because -1PyPy: ffi.new() and ffi.new_allocator()() did not
record 'memory pressure';, causing the GC to run too infrequently if
you call ffi.new() very often and/or with large arrays. Fixed in PyPy
5.7.

Support in ffi.cdef() for numeric expressions with + or -. Assumes
that there is no overflow; it should be fixed first before we add more
general support for arbitrary arithmetic on constants.

</cdata></cdata></cdata>

Update to 1.9.1: Structs with variable-sized arrays as their last
field: now we track the length of the array after ffi.new() is called,
just like we always tracked the length of ffi.new('int[]', 42). This
lets us detect out-of-range accesses to array items. This also lets us
display a better repr(), and have the total size returned by
ffi.sizeof() and ffi.buffer(). Previously both functions would return
a result based on the size of the declared structure type, with an
assumed empty array. (Thanks andrew for starting this refactoring.)

Add support in cdef()/set_source() for unspecified-length arrays in
typedefs: typedef int foo_t[...];. It was already supported for global
variables or structure fields.

I turned in v1.8 a warning from cffi/model.py into an error: 'enum
xxx' has no values explicitly defined: refusing to guess which integer
type it is meant to be (unsigned/signed, int/long). Now I'm turning it
back to a warning again; it seems that guessing that the enum has size
int is a 99%-safe bet. (But not 100%, so it stays as a warning.)

Fix leaks in the code handling FILE * arguments. In CPython 3 there is
a remaining issue that is hard to fix: if you pass a Python file
object to a FILE * argument, then os.dup() is used and the new file
descriptor is only closed when the GC reclaims the Python file
object-and not at the earlier time when you call close(), which only
closes the original file descriptor. If this is an issue, you should
avoid this automatic convertion of Python file objects: instead,
explicitly manipulate file descriptors and call fdopen() from C
(...via cffi).

When passing a void * argument to a function with a different pointer
type, or vice-versa, the cast occurs automatically, like in C. The
same occurs for initialization with ffi.new() and a few other places.
However, I thought that char * had the same property-but I was
mistaken. In C you get the usual warning if you try to give a char *
to a char ** argument, for example. Sorry about the confusion. This
has been fixed in CFFI by giving for now a warning, too. It will turn
into an error in a future version.

Issue #283: fixed ffi.new() on structures/unions with nested anonymous
structures/unions, when there is at least one union in the mix. When
initialized with a list or a dict, it should now behave more closely
like the { } syntax does in GCC.

CPython 3.x: experimental: the generated C extension modules now use
the 'limited API';, which means that, as a compiled .so/.dll, it
should work directly on any version of CPython >= 3.2. The name
produced by distutils is still version-specific. To get the
version-independent name, you can rename it manually to NAME.abi3.so,
or use the very recent setuptools 26.

Added ffi.compile(debug=...), similar to python setup.py build --debug
but defaulting to True if we are running a debugging version of Python
itself.

Removed the restriction that ffi.from_buffer() cannot be used on byte
strings. Now you can get a char * out of a byte string, which is valid
as long as the string object is kept alive. (But don't use it to
modify the string object! If you need this, use bytearray or other
official techniques.)

PyPy 5.4 can now pass a byte string directly to a char * argument (in
older versions, a copy would be made). This used to be a CPython-only
optimization.

ffi.gc(p, None) removes the destructor on an object previously created
by another call to ffi.gc()

bool(ffi.cast('primitive type', x)) now returns False if the value is
zero (including -0.0), and True otherwise. Previously this would only
return False for cdata objects of a pointer type when the pointer is
NULL.

bytearrays: ffi.from_buffer(bytearray-object) is now supported. (The
reason it was not supported was that it was hard to do in PyPy, but it
works since PyPy 5.3.) To call a C function with a char * argument
from a buffer object-now including
bytearrays&Atilde;&cent;&Acirc;&#128;&Acirc;&#148;you write
lib.foo(ffi.from_buffer(x)). Additionally, this is now supported:
p[0:length] = bytearray-object. The problem with this was that a
iterating over bytearrays gives numbers instead of characters. (Now it
is implemented with just a memcpy, of course, not actually iterating
over the characters.)

C++: compiling the generated C code with C++ was supposed to work, but
failed if you make use the bool type (because that is rendered as the
C _Bool type, which doesn't exist in C++).

help(lib) and help(lib.myfunc) now give useful information, as well as
dir(p) where p is a struct or pointer-to-struct.

Fixed the 'negative left shift' warning by replacing bitshifting in
appropriate places by bitwise and comparison to self; patch taken from
upstream git. Drop cffi-1.5.2-wnoerror.patch: no longer required.

disable 'negative left shift' warning in test suite to prevent
failures with gcc6, until upstream fixes the undefined code in
question (bsc#981848)

Update to version 1.6.0: ffi.list_types()

ffi.unpack()

extern 'Python+C';

in API mode, lib.foo.__doc__ contains the C signature now.

Yet another attempt at robustness of ffi.def_extern() against
CPython's interpreter shutdown logic.

Update to 1.5.2: support for cffi-based embedding

more robustness for shutdown logic

Updated python-cryptography to 2.1.4 (bsc#1138748, jsc#ECO-1256,
jsc#PM-1598) Make this version of the package compatible with OpenSSL
1.1.1d (bsc#1149792)

CVE-2018-10903: Fixed GCM tag forgery via truncated tag in
finalize_with_tag API (bsc#1101820)

Update to version 2.1.4: Added X509_up_ref for an upcoming pyOpenSSL
release.

Corrected a bug with the manylinux1 wheels where OpenSSL's stack was
marked executable.

support for OpenSSL 1.0.0 has been removed.

Added support for Diffie-Hellman key exchange

The OS random engine for OpenSSL has been rewritten

python-xattr was just rebuilt to adjust its cffi depedency.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1138748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10903/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200790-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3bd67c6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6-LTSS:zypper in -t patch
SUSE-OpenStack-Cloud-6-LTSS-2020-790=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2020-790=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2020-790=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-cffi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-cffi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-cryptography-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-cryptography-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-xattr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-xattr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-xattr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cryptography");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-cffi-1.11.2-2.19.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-cffi-debuginfo-1.11.2-2.19.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-cffi-debugsource-1.11.2-2.19.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-cryptography-2.1.4-3.15.5")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-cryptography-debuginfo-2.1.4-3.15.5")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-cryptography-debugsource-2.1.4-3.15.5")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-xattr-0.7.5-3.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-xattr-debuginfo-0.7.5-3.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-xattr-debugsource-0.7.5-3.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-cffi-1.11.2-2.19.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-cryptography-2.1.4-3.15.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-cffi / python-cryptography / python-xattr");
}
