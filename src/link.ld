ENTRY(main);

SECTIONS
{
  /* -------- Read-only --------- */
  . = 0x10000000;

  .text :
  {
    *(.text .text.*);
    . = ALIGN(4);
  }

  .rodata : ALIGN(4)
  {
    *(.rodata .rodata.*);
    . = ALIGN(4);
  }

  /* -------- Read-write --------- */

  . = ALIGN(4096);
  _ram_start = .;

  .data : ALIGN(4)
  {
    *(.data .data.*);
    . = ALIGN(4);
  }

  .bss : ALIGN(4)
  {
    *(.bss .bss.*);

    /* Initial stack */
    . += 65536;
    . = ALIGN(16);
    _stack_start = .;
  }

  /* It's up to the user to use this wisely :) */
  . = ALIGN(4);
  __sheap = .;
  . += 0x100000;
  __eheap = .;

  . = ALIGN(4096);
  _ram_end = .;

  /* -------- That's all! --------- */

  /* Dynamic relocations are unsupported. This section is only used to detect relocatable code in
     the input files and raise an error if relocatable code is found */
  .got (NOLOAD) :
  {
    KEEP(*(.got .got.*));
  }

  /DISCARD/ :
  {
    *(.ARM.exidx);
    *(.ARM.exidx.*);
    *(.ARM.extab.*);
  }
}
