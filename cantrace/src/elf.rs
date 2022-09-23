use object::elf::{
    FileHeader64, DF_1_CONFALT, DF_1_DIRECT, DF_1_DISPRELDNE, DF_1_DISPRELPND, DF_1_EDITED,
    DF_1_ENDFILTEE, DF_1_GLOBAL, DF_1_GLOBAUDIT, DF_1_GROUP, DF_1_IGNMULDEF, DF_1_INITFIRST,
    DF_1_INTERPOSE, DF_1_LOADFLTR, DF_1_NODEFLIB, DF_1_NODELETE, DF_1_NODIRECT, DF_1_NODUMP,
    DF_1_NOHDR, DF_1_NOKSYMS, DF_1_NOOPEN, DF_1_NORELOC, DF_1_NOW, DF_1_ORIGIN, DF_1_PIE,
    DF_1_SINGLETON, DF_1_STUB, DF_1_SYMINTPOSE, DF_1_TRANS, DT_FLAGS, DT_FLAGS_1, DT_STRSZ,
    DT_STRTAB, PT_DYNAMIC,
};
use object::read::elf::{Dyn, FileHeader, ProgramHeader};
use object::{
    Endianness, File, FileKind, Object, ObjectSection, ObjectSegment, ObjectSymbol, StringTable,
};
use yaxpeax_arch::LengthedInstruction;
use yaxpeax_x86::amd64::{InstDecoder, Opcode};

struct Flag<T> {
    value: T,
    name: &'static str,
}

macro_rules! flags {
    ($($name:ident),+ $(,)?) => ( [ $(Flag { value: $name, name: stringify!($name), }),+ ] )
}

static FLAGS_DF_1: &[Flag<u32>] = &flags!(
    DF_1_NOW,
    DF_1_GLOBAL,
    DF_1_GROUP,
    DF_1_NODELETE,
    DF_1_LOADFLTR,
    DF_1_INITFIRST,
    DF_1_NOOPEN,
    DF_1_ORIGIN,
    DF_1_DIRECT,
    DF_1_TRANS,
    DF_1_INTERPOSE,
    DF_1_NODEFLIB,
    DF_1_NODUMP,
    DF_1_CONFALT,
    DF_1_ENDFILTEE,
    DF_1_DISPRELDNE,
    DF_1_DISPRELPND,
    DF_1_NODIRECT,
    DF_1_IGNMULDEF,
    DF_1_NOKSYMS,
    DF_1_NOHDR,
    DF_1_EDITED,
    DF_1_NORELOC,
    DF_1_SYMINTPOSE,
    DF_1_GLOBAUDIT,
    DF_1_SINGLETON,
    DF_1_STUB,
    DF_1_PIE,
);

/// Get the address of the first ret after the entry point...lmao
pub fn get_start_exit(data: &[u8], base: u64) -> u64 {
    let binfile = File::parse(data).unwrap();
    let is_pie = is_pie(data);
    let mut main_addr = 0;
    // println!("Base @ 0x{:x}", base);
    for symbol in binfile.symbols() {
        // println!("{:016x} {}", symbol.address(), symbol.name().unwrap());
        if symbol.name().unwrap() == "main" {
            if !is_pie {
                main_addr = symbol.address() - base;
            } else {
                main_addr = symbol.address();
            }
        }
    }
    assert!(
        main_addr != 0,
        "No main symbol found, can't figure out when the program ends"
    );

    let decoder = InstDecoder::default();
    let mut offset = main_addr;
    while offset < data.len().try_into().unwrap() {
        let inst = decoder
            .decode_slice(&data[offset as usize..(offset + 16) as usize])
            .unwrap();
        if let Opcode::RETURN = inst.opcode() {
            return offset;
        }
        offset += inst.len();
    }
    unreachable!("No ret found after main");
}

/// Get the address of the first loadable segment in the ELF file.
pub fn get_load_base(data: &[u8]) -> u64 {
    let binfile = File::parse(data).unwrap();
    for segment in binfile.segments() {
        return segment.address();
    }
    0
}

pub fn get_text(data: &[u8]) -> u64 {
    let binfile = File::parse(data).unwrap();
    binfile.section_by_name(".text").unwrap().address()
}

pub fn is_pie(data: &[u8]) -> bool {
    // let pic_bin_file = read(path).expect("failed to read test");
    // let data: &[u8] = &pic_bin_file[..];

    let kind = match FileKind::parse(data) {
        Ok(file) => file,
        Err(err) => {
            assert!(false, "failed to parse file kind: {}", err);
            unreachable!()
        }
    };

    match kind {
        FileKind::Elf64 => {
            if let Ok(elf) = FileHeader64::<Endianness>::parse(data) {
                if let Ok(endian) = elf.endian() {
                    if let Ok(segments) = elf.program_headers(endian, data) {
                        for segment in segments {
                            match segment.p_type(endian) {
                                PT_DYNAMIC => {
                                    if let Ok(Some(dynamic)) = segment.dynamic(endian, data) {
                                        let mut strtab = 0;
                                        let mut strsz = 0;
                                        for d in dynamic {
                                            let tag: u64 = d.d_tag(endian).into();
                                            if tag == DT_STRTAB.into() {
                                                strtab = d.d_val(endian);
                                            } else if tag == DT_STRSZ.into() {
                                                strsz = d.d_val(endian);
                                            }
                                        }
                                        for s in segments {
                                            if let Ok(Some(dynstr_data)) =
                                                s.data_range(endian, data, strtab, strsz)
                                            {
                                                let _dynstr = StringTable::new(
                                                    dynstr_data,
                                                    0,
                                                    dynstr_data.len() as u64,
                                                );
                                                for d in dynamic {
                                                    let itag: u64 = d.d_tag(endian).into();
                                                    let val: u64 = d.d_val(endian).into();
                                                    if let Some(tag) = d.tag32(endian) {
                                                        if !d.is_string(endian) {
                                                            if itag == DT_FLAGS.into() {
                                                                // val, 0, flags_df
                                                            } else if itag == DT_FLAGS_1.into() {
                                                                // val, 0, flags_df_1
                                                                for flag in FLAGS_DF_1 {
                                                                    if val
                                                                        & <u32 as Into<u64>>::into(
                                                                            flag.value,
                                                                        )
                                                                        == flag.value.into()
                                                                    {
                                                                        return true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        _ => {
            assert!(false, "unsupported file kind: {:?}", kind);
        }
    }
    return false;
}
