#![feature(rustc_attrs)]
#![feature(no_core)]
#![no_core]
#![no_main]

#[rustc_builtin_macro]
macro_rules! global_asm {
    () => {
        /* compiler built-in */
    };
}

#[rustfmt::skip]
global_asm!(r###"
.text
.global implicit_main
implicit_main:
{code}
ret
"###);
