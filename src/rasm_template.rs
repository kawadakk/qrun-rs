#![feature(global_asm)]
#![feature(lang_items)]
#![no_std]
#![no_main]

#[rustfmt::skip]
global_asm!(r###"
.text
.global implicit_main
implicit_main:
{code}
ret
"###);

#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[lang = "eh_personality"]
extern "C" fn rust_eh_personality() {}
