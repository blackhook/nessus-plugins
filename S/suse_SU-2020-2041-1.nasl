#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2041-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(138995);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-1967");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : rust, rust-cbindgen (SUSE-SU-2020:2041-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for rust, rust-cbindgen fixes the following issues :

rust was updated for use by Firefox 76ESR.

Fixed miscompilations with rustc 1.43 that lead to LTO failures
(bsc#1173202)

Update to version 1.43.1

Updated openssl-src to 1.1.1g for CVE-2020-1967.

Fixed the stabilization of AVX-512 features.

Fixed `cargo package --list` not working with unpublished
dependencies.

Update to version 1.43.0

Language :

Fixed using binary operations with `&{number}` (e.g. `&1.0`) not
having the type inferred correctly.

Attributes such as `#[cfg()]` can now be used on `if` expressions.

Syntax only changes :

  - Allow `type Foo: Ord` syntactically.

  - Fuse associated and extern items up to defaultness.

  - Syntactically allow `self` in all `fn` contexts.

  - Merge `fn` syntax + cleanup item parsing.

  - `item` macro fragments can be interpolated into
    `trait`s, `impl`s, and `extern` blocks. For example, you
    may now write: ```rust macro_rules! mac_trait {
    ($i:item) => { trait T { $i } } } mac_trait! { fn foo()
    {} } ```

  - These are still rejected *semantically*, so you will
    likely receive an error but these changes can be seen
    and parsed by macros and conditional compilation.

Compiler

You can now pass multiple lint flags to rustc to override the previous
flags.

For example; `rustc -D unused -A unused-variables` denies everything
in the `unused` lint group except `unused-variables` which is
explicitly allowed. However, passing `rustc -A unused-variables -D
unused` denies everything in the `unused` lint group **including**
`unused-variables` since the allow flag is specified before the deny
flag (and therefore overridden). rustc will now prefer your system
MinGW libraries over its bundled libraries if they are available on
`windows-gnu`.

rustc now buffers errors/warnings printed in JSON.

Libraries :

`Arc<[T; N]>`, `Box<[T; N]>`, and `Rc<[T; N]>`, now implement
`TryFrom<Arc<[T]>>`,`TryFrom<Box<[T]>>`, and `TryFrom<Rc<[T]>>`
respectively.

**Note** These conversions are only available when `N` is `0..=32`.

You can now use associated constants on floats and integers directly,
rather than having to import the module. e.g. You can now write
`u32::MAX` or `f32::NAN` with no imports.

`u8::is_ascii` is now `const`.

`String` now implements `AsMut<str>`.

Added the `primitive` module to `std` and `core`. This module
reexports Rust's primitive types. This is mainly useful in macros
where you want avoid these types being shadowed.

Relaxed some of the trait bounds on `HashMap` and `HashSet`.

`string::FromUtf8Error` now implements `Clone + Eq`.

Stabilized APIs

`Once::is_completed`

`f32::LOG10_2`

`f32::LOG2_10`

`f64::LOG10_2`

`f64::LOG2_10`

`iter::once_with`

Cargo

  - You can now set config `[profile]`s in your
    `.cargo/config`, or through your environment.

  - Cargo will now set `CARGO_BIN_EXE_<name>` pointing to a
    binary's executable path when running integration tests
    or benchmarks. `<name>` is the name of your binary as-is
    e.g. If you wanted the executable path for a binary
    named `my-program`you would use
    `env!('CARGO_BIN_EXE_my-program')`.

Misc

  - Certain checks in the `const_err` lint were deemed
    unrelated to const evaluation, and have been moved to
    the `unconditional_panic` and `arithmetic_overflow`
    lints.

Compatibility Notes

  - Having trailing syntax in the `assert!` macro is now a
    hard error. This has been a warning since 1.36.0.

  - Fixed `Self` not having the correctly inferred type.
    This incorrectly led to some instances being accepted,
    and now correctly emits a hard error.

Update to version 1.42.0 :

Language

  - You can now use the slice pattern syntax with subslices.

  - You can now use #[repr(transparent)] on univariant
    enums. Meaning that you can create an enum that has the
    exact layout and ABI of the type it contains.

  - There are some syntax-only changes :

  - default is syntactically allowed before items in trait
    definitions.

  - Items in impls (i.e. consts, types, and fns) may
    syntactically leave out their bodies in favor of ;.

  - Bounds on associated types in impls are now
    syntactically allowed (e.g. type Foo: Ord;).

  - ... (the C-variadic type) may occur syntactically
    directly as the type of any function parameter. These
    are still rejected semantically, so you will likely
    receive an error but these changes can be seen and
    parsed by procedural macros and conditional compilation.

Compiler

  - Added tier 2 support for armv7a-none-eabi.

  - Added tier 2 support for riscv64gc-unknown-linux-gnu.

  - Option::{expect,unwrap} and Result::{expect, expect_err,
    unwrap, unwrap_err} now produce panic messages pointing
    to the location where they were called, rather than
    core's internals. Refer to Rust's platform support page
    for more information on Rust's tiered platform support.

Libraries

  - iter::Empty<T> now implements Send and Sync for any T.

  - Pin::{map_unchecked, map_unchecked_mut} no longer
    require the return type to implement Sized.

  - io::Cursor now derives PartialEq and Eq.

  - Layout::new is now const.

  - Added Standard Library support for
    riscv64gc-unknown-linux-gnu.

Stabilized APIs

  - CondVar::wait_while

  - CondVar::wait_timeout_while

  - DebugMap::key

  - DebugMap::value

  - ManuallyDrop::take

  - matches!

  - ptr::slice_from_raw_parts_mut

  - ptr::slice_from_raw_parts

Cargo

  - You no longer need to include extern crate proc_macro;
    to be able to use proc_macro; in the 2018 edition.

Compatibility Notes

  - Error::description has been deprecated, and its use will
    now produce a warning. It's recommended to use
    Display/to_string instead.

Update to version 1.41.1 :

  - Always check types of static items

  - Always check lifetime bounds of `Copy` impls

  - Fix miscompilation in callers of `Layout::repeat`

Update to version 1.41.0 :

Language

  - You can now pass type parameters to foreign items when
    implementing traits. E.g. You can now write `impl<T>
    From<Foo> for Vec<T> {}`.

  - You can now arbitrarily nest receiver types in the
    `self` position. E.g. you can now write `fn foo(self:
    Box<Box<Self>>) {}`. Previously only `Self`, `&Self`,
    `&mut Self`, `Arc<Self>`, `Rc<Self>`, and `Box<Self>`
    were allowed.

  - You can now use any valid identifier in a `format_args`
    macro. Previously identifiers starting with an
    underscore were not allowed.

  - Visibility modifiers (e.g. `pub`) are now syntactically
    allowed on trait items and enum variants. These are
    still rejected semantically, but can be seen and parsed
    by procedural macros and conditional compilation.

Compiler

  - Rustc will now warn if you have unused loop `'label`s.

  - Removed support for the `i686-unknown-dragonfly` target.

  - Added tier 3 support\* for the
    `riscv64gc-unknown-linux-gnu` target.

  - You can now pass an arguments file passing the `@path`
    syntax to rustc. Note that the format differs somewhat
    from what is found in other tooling; please see the
    documentation for more information.

  - You can now provide `--extern` flag without a path,
    indicating that it is available from the search path or
    specified with an `-L` flag.

    Refer to Rust's [platform support
    page][forge-platform-support] for more information on
    Rust's tiered platform support.

Libraries

  - The `core::panic` module is now stable. It was already
    stable through `std`.

  - `NonZero*` numerics now implement `From<NonZero*>` if
    it's a smaller integer width. E.g. `NonZeroU16` now
    implements `From<NonZeroU8>`.

  - `MaybeUninit<T>` now implements `fmt::Debug`.

Stabilized APIs

  - `Result::map_or`

  - `Result::map_or_else`

  - `std::rc::Weak::weak_count`

  - `std::rc::Weak::strong_count`

  - `std::sync::Weak::weak_count`

  - `std::sync::Weak::strong_count`

Cargo

  - Cargo will now document all the private items for binary
    crates by default.

  - `cargo-install` will now reinstall the package if it
    detects that it is out of date.

  - Cargo.lock now uses a more git friendly format that
    should help to reduce merge conflicts.

  - You can now override specific dependencies's build
    settings. E.g. `[profile.dev.package.image] opt-level =
    2` sets the `image` crate's optimisation level to `2`
    for debug builds. You can also use
    `[profile.<profile>.build-override]` to override build
    scripts and their dependencies.

Misc

  - You can now specify `edition` in documentation code
    blocks to compile the block for that edition. E.g.
    `edition2018` tells rustdoc that the code sample should
    be compiled the 2018 edition of Rust.

  - You can now provide custom themes to rustdoc with
    `--theme`, and check the current theme with
    `--check-theme`.

  - You can use `#[cfg(doc)]` to compile an item when
    building documentation.

Compatibility Notes

  - As previously announced 1.41.0 will be the last tier 1
    release for 32-bit Apple targets. This means that the
    source code is still available to build, but the targets
    are no longer being tested and release binaries for
    those platforms will no longer be distributed by the
    Rust project. Please refer to the linked blog post for
    more information.

Bump version of libssh2 for SLE15; we now need a version with
libssh2_userauth_publickey_frommemory(), which appeared in libssh2
1.6.0.

Update to version 1.40.0

Language

  - You can now use tuple `struct`s and tuple `enum`
    variant's constructors in `const` contexts. e.g. pub
    struct Point(i32, i32); const ORIGIN: Point = { let
    constructor = Point; constructor(0, 0) };

  - You can now mark `struct`s, `enum`s, and `enum` variants
    with the `#[non_exhaustive]` attribute to indicate that
    there may be variants or fields added in the future. For
    example this requires adding a wild-card branch (`_ =>
    {}`) to any match statements on a non-exhaustive `enum`.

  - You can now use function-like procedural macros in
    `extern` blocks and in type positions. e.g. `type
    Generated = macro!();`

  - Function-like and attribute procedural macros can now
    emit `macro_rules!` items, so you can now have your
    macros generate macros.

  - The `meta` pattern matcher in `macro_rules!` now
    correctly matches the modern attribute syntax. For
    example `(#[$m:meta])` now matches `#[attr]`,
    `#[attr{tokens}]`, `#[attr[tokens]]`, and
    `#[attr(tokens)]`.

Compiler

  - Added tier 3 support\* for the
    `thumbv7neon-unknown-linux-musleabihf` target.

  - Added tier 3 support for the
    `aarch64-unknown-none-softfloat` target.

  - Added tier 3 support for the
    `mips64-unknown-linux-muslabi64`, and
    `mips64el-unknown-linux-muslabi64` targets.

Libraries

  - The `is_power_of_two` method on unsigned numeric types
    is now a `const` function.

Stabilized APIs

  - BTreeMap::get_key_value

  - HashMap::get_key_value

  - Option::as_deref_mut

  - Option::as_deref

  - Option::flatten

  - UdpSocket::peer_addr

  - f32::to_be_bytes

  - f32::to_le_bytes

  - f32::to_ne_bytes

  - f64::to_be_bytes

  - f64::to_le_bytes

  - f64::to_ne_bytes

  - f32::from_be_bytes

  - f32::from_le_bytes

  - f32::from_ne_bytes

  - f64::from_be_bytes

  - f64::from_le_bytes

  - f64::from_ne_bytes

  - mem::take

  - slice::repeat

  - todo!

Cargo

  - Cargo will now always display warnings, rather than only
    on fresh builds.

  - Feature flags (except `--all-features`) passed to a
    virtual workspace will now produce an error. Previously
    these flags were ignored.

  - You can now publish `dev-dependencies` without including
    a `version`.

Misc

  - You can now specify the `#[cfg(doctest)]` attribute to
    include an item only when running documentation tests
    with `rustdoc`.

Compatibility Notes

  - As previously announced, any previous NLL warnings in
    the 2015 edition are now hard errors.

  - The `include!` macro will now warn if it failed to
    include the entire file. The `include!` macro
    unintentionally only includes the first _expression_ in
    a file, and this can be unintuitive. This will become
    either a hard error in a future release, or the behavior
    may be fixed to include all expressions as expected.

  - Using `#[inline]` on function prototypes and consts now
    emits a warning under `unused_attribute` lint. Using
    `#[inline]` anywhere else inside traits or `extern`
    blocks now correctly emits a hard error.

Update to version 1.39.0

Language

  - You can now create async functions and blocks with async
    fn, async move {}, and async {} respectively, and you
    can now call .await on async expressions.

  - You can now use certain attributes on function, closure,
    and function pointer parameters.

  - You can now take shared references to bind-by-move
    patterns in the if guards of match arms.

Compiler

  - Added tier 3 support for the i686-unknown-uefi target.

  - Added tier 3 support for the sparc64-unknown-openbsd
    target.

  - rustc will now trim code snippets in diagnostics to fit
    in your terminal.

  - You can now pass --show-output argument to test binaries
    to print the output of successful tests.

For more details :

https://github.com/rust-lang/rust/blob/stable/RELEASES.md#version-1390
-2019

-11-07

Switch to bundled version of libgit2 for now. libgit2-sys seems to
expect using the bundled variant, which just seems to point to a
snapshot of the master branch and doesn't match any released libgit2
(bsc#1154817). See: https://github.com/rust-lang/rust/issues/63476 and
https://github.com/rust-lang/git2-rs/issues/458 for details.

Update to version 1.38.0

Language

  - The `#[global_allocator]` attribute can now be used in
    submodules.

  - The `#[deprecated]` attribute can now be used on macros.

Compiler

  - Added pipelined compilation support to `rustc`. This
    will improve compilation times in some cases.

Libraries

  - `ascii::EscapeDefault` now implements `Clone` and
    `Display`.

  - Derive macros for prelude traits (e.g. `Clone`, `Debug`,
    `Hash`) are now available at the same path as the trait.
    (e.g. The `Clone` derive macro is available at
    `std::clone::Clone`). This also makes all built-in
    macros available in `std`/`core` root. e.g.
    `std::include_bytes!`.

  - `str::Chars` now implements `Debug`.

  - `slice::{concat, connect, join}` now accepts `&[T]` in
    addition to `&T`.

  - `*const T` and `*mut T` now implement `marker::Unpin`.

  - `Arc<[T]>` and `Rc<[T]>` now implement
    `FromIterator<T>`.

  - Added euclidean remainder and division operations
    (`div_euclid`, `rem_euclid`) to all numeric primitives.
    Additionally `checked`, `overflowing`, and `wrapping`
    versions are available for all integer primitives.

  - `thread::AccessError` now implements `Clone`, `Copy`,
    `Eq`, `Error`, and `PartialEq`.

  - `iter::{StepBy, Peekable, Take}` now implement
    `DoubleEndedIterator`.

Stabilized APIs

  - `<*const T>::cast`

  - `<*mut T>::cast`

  - `Duration::as_secs_f32`

  - `Duration::as_secs_f64`

  - `Duration::div_f32`

  - `Duration::div_f64`

  - `Duration::from_secs_f32`

  - `Duration::from_secs_f64`

  - `Duration::mul_f32`

  - `Duration::mul_f64`

  - `any::type_name`

Cargo

  - Added pipelined compilation support to `cargo`.

  - You can now pass the `--features` option multiple times
    to enable multiple features.

Misc

  - `rustc` will now warn about some incorrect uses of
    `mem::{uninitialized, zeroed}` that are known to cause
    undefined behaviour.

Update to version 1.37.0

  + Language

  - #[must_use] will now warn if the type is contained in a
    tuple, Box, or an array and unused.

  - You can now use the `cfg` and `cfg_attr` attributes on
    generic parameters.

  - You can now use enum variants through type alias. e.g.
    You can write the following: ``` type MyOption =
    Option<u8>; fn increment_or_zero(x: MyOption) -> u8 {
    match x { MyOption::Some(y) => y + 1, MyOption::None =>
    0, } } ```

  - You can now use `_` as an identifier for consts. e.g.
    You can write `const _: u32 = 5;`.

  - You can now use `#[repr(align(X)]` on enums.

  - The `?` Kleene macro operator is now available in the
    2015 edition.

  + Compiler

  - You can now enable Profile-Guided Optimization with the
    `-C profile-generate` and `-C profile-use` flags. For
    more information on how to use profile guided
    optimization, please refer to the rustc book.

  - The `rust-lldb` wrapper script should now work again.

  + Libraries

  - `mem::MaybeUninit<T>` is now ABI-compatible with `T`.

  + Stabilized APIs

  - BufReader::buffer

  - BufWriter::buffer

  - Cell::from_mut

  - Cell<[T]>::as_slice_of_cells

  - Cell<slice>::as_slice_of_cells

  - DoubleEndedIterator::nth_back

  - Option::xor

  - Wrapping::reverse_bits

  - i128::reverse_bits

  - i16::reverse_bits

  - i32::reverse_bits

  - i64::reverse_bits

  - i8::reverse_bits

  - isize::reverse_bits

  - slice::copy_within

  - u128::reverse_bits

  - u16::reverse_bits

  - u32::reverse_bits

  - u64::reverse_bits

  - u8::reverse_bits

  - usize::reverse_bits

  + Cargo

  - Cargo.lock files are now included by default when
    publishing executable crates with executables.

  - You can now specify `default-run='foo'` in `[package]`
    to specify the default executable to use for `cargo
    run`.

  - cargo-vendor is now provided as a sub-command of cargo

  + Compatibility Notes

  - Using `...` for inclusive range patterns will now warn
    by default. Please transition your code to using the
    `..=` syntax for inclusive ranges instead.

  - Using a trait object without the `dyn` will now warn by
    default. Please transition your code to use `dyn Trait`
    for trait objects instead. Crab(String),
    Lobster(String), Person(String), let state =
    Creature::Crab('Ferris'); if let Creature::Crab(name) |
    Creature::Person(name) = state { println!('This
    creature's name is: {}', name); } unsafe { foo() } pub
    fn new(x: i32, y: i32) -> Self { Self(x, y) } pub fn
    is_origin(&self) -> bool { match self { Self(0, 0) =>
    true, _ => false, } } Self: PartialOrd<Self> // can
    write `Self` instead of `List<T>` Nil, Cons(T,
    Box<Self>) // likewise here fn test(&self) {
    println!('one'); } //~ ERROR duplicate definitions with
    name `test` fn test(&self) { println!('two'); }

Basic procedural macros allowing custom `#[derive]`, aka 'macros 1.1',
are stable. This allows popular code-generating crates like Serde and
Diesel to work ergonomically. [RFC 1681].

[Tuple structs may be empty. Unary and empty tuple structs may be
instantiated with curly braces][36868]. Part of [RFC 1506].

[A number of minor changes to name resolution have been
activated][37127]. They add up to more consistent semantics, allowing
for future evolution of Rust macros. Specified in [RFC 1560], see its
section on ['changes'] for details of what is different. The breaking
changes here have been transitioned through the [`legacy_imports`]
lint since 1.14, with no known regressions.

[In `macro_rules`, `path` fragments can now be parsed as type
parameter bounds][38279]

[`?Sized` can be used in `where` clauses][37791]

[There is now a limit on the size of monomorphized types and it can be
modified with the `#![type_size_limit]` crate attribute, similarly to
the `#![recursion_limit]` attribute][37789]

[On Windows, the compiler will apply dllimport attributes when linking
to extern functions][37973]. Additional attributes and flags can
control which library kind is linked and its name. [RFC 1717].

[Rust-ABI symbols are no longer exported from cdylibs][38117]

[The `--test` flag works with procedural macro crates][38107]

[Fix `extern 'aapcs' fn` ABI][37814]

[The `-C no-stack-check` flag is deprecated][37636]. It does nothing.

[The `format!` expander recognizes incorrect `printf` and shell-style
formatting directives and suggests the correct format][37613].

[Only report one error for all unused imports in an import
list][37456]

[Avoid unnecessary `mk_ty` calls in `Ty::super_fold_with`][37705]

[Avoid more unnecessary `mk_ty` calls in `Ty::super_fold_with`][37979]

[Don't clone in `UnificationTable::probe`][37848]

[Remove `scope_auxiliary` to cut RSS by 10%][37764]

[Use small vectors in type walker][37760]

[Macro expansion performance was improved][37701]

[Change `HirVec<P<T>>` to `HirVec<T>` in `hir::Expr`][37642]

[Replace FNV with a faster hash function][37229]
https://raw.githubusercontent.com/rust-lang/rust/master/RELEASES.md

rust-cbindgen is shipped in version 0.14.1.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1115645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1154817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173202");
  script_set_attribute(attribute:"see_also", value:"https://github.com/rust-lang/git2-rs/issues/458");
  # https://github.com/rust-lang/rust/blob/stable/RELEASES.md#version-1390-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cddb404e");
  script_set_attribute(attribute:"see_also", value:"https://github.com/rust-lang/rust/issues/63476");
  script_set_attribute(attribute:"see_also", value:"https://raw.githubusercontent.com/rust-lang/rust/master/RELEASES.md");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1967/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202041-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44adf694");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Development Tools 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP2-2020-2041=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP1-2020-2041=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cargo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cargo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clippy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clippy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rust-analysis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rust-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rust-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rust-std-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rustfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rustfmt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"cargo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cargo-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"clippy-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"clippy-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rls-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rls-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rust-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rust-analysis-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rust-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rust-debugsource-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rust-std-static-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rustfmt-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rustfmt-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"cargo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"cargo-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"clippy-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"clippy-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rls-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rls-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rust-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rust-analysis-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rust-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rust-debugsource-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rust-std-static-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rustfmt-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"rustfmt-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cargo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cargo-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"clippy-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"clippy-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rls-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rls-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rust-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rust-analysis-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rust-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rust-debugsource-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rust-std-static-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rustfmt-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rustfmt-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"cargo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"cargo-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"clippy-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"clippy-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rls-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rls-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rust-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rust-analysis-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rust-debuginfo-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rust-debugsource-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rust-std-static-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rustfmt-1.43.1-12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"rustfmt-debuginfo-1.43.1-12.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rust / rust-cbindgen");
}
