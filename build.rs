//! Windows only: puts the jetscan icon (`docs/brand/jetscan.ico`) into `jetscan.exe`, so
//! Explorer, the taskbar and the file's Properties show it.
//!
//! No crates and no resource compiler (rc.exe / windres): an icon resource is just the ICO's
//! images plus a small directory, so this script writes the compiled form itself:
//! - MSVC targets: a `.res` file, which `link.exe` (and `lld-link`) take as an input and
//!   convert with their built-in CVTRES step;
//! - GNU targets: a COFF object with a `.rsrc` section (what `windres` would produce),
//!   because GNU `ld` does not read `.res` files.
//!
//! It never fails the build: off Windows it does nothing, and if the icon is missing or
//! unreadable, or the target is another Windows flavour, the exe is built without an icon.
//!
//! Formats (Win32 and PE/COFF docs on learn.microsoft.com): RESOURCEHEADER, GRPICONDIR /
//! GRPICONDIRENTRY, and "The .rsrc Section" of the PE format.

use std::env;
use std::fs;
use std::path::PathBuf;

const ICON: &str = "docs/brand/jetscan.ico";
const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;

/// One resource: numeric type, numeric name, memory flags (`.res` only), bytes.
struct Resource {
    kind: u16,
    id: u16,
    flags: u16,
    data: Vec<u8>,
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={ICON}");
    let var = |name: &str| env::var(name).unwrap_or_default();
    if var("CARGO_CFG_TARGET_OS") != "windows" {
        return;
    }
    let (Some(manifest), Some(out)) = (env::var_os("CARGO_MANIFEST_DIR"), env::var_os("OUT_DIR"))
    else {
        return;
    };
    let Ok(ico) = fs::read(PathBuf::from(manifest).join(ICON)) else {
        return; // a source tree without the icon: build without one
    };
    let Some(resources) = icon_resources(&ico) else {
        println!("cargo:warning={ICON} is not a valid .ico; jetscan.exe is built without an icon");
        return;
    };
    let (name, bytes) = match (
        var("CARGO_CFG_TARGET_ENV").as_str(),
        var("CARGO_CFG_TARGET_ARCH").as_str(),
    ) {
        ("msvc", _) => ("jetscan-icon.res", res_file(&resources)),
        // (COFF machine, ADDR32NB relocation type) for GNU ld.
        ("gnu", "x86_64") => ("jetscan-icon.o", coff_object(&resources, 0x8664, 3)),
        ("gnu", "x86") => ("jetscan-icon.o", coff_object(&resources, 0x014c, 7)),
        ("gnu", "aarch64") => ("jetscan-icon.o", coff_object(&resources, 0xaa64, 2)),
        _ => return,
    };
    let path = PathBuf::from(out).join(name);
    if fs::write(&path, bytes).is_ok() {
        // Only the executables: tests, examples and benches do not need an icon.
        println!("cargo:rustc-link-arg-bins={}", path.display());
    }
}

/// The resources for an ICO file: one RT_ICON per image (ids 1..n) and one RT_GROUP_ICON
/// (id 1) listing them. `None` if the ICO is malformed.
fn icon_resources(ico: &[u8]) -> Option<Vec<Resource>> {
    let u16_at = |i: usize| Some(u16::from_le_bytes(ico.get(i..i + 2)?.try_into().ok()?));
    let u32_at = |i: usize| Some(u32::from_le_bytes(ico.get(i..i + 4)?.try_into().ok()?));
    if u16_at(0)? != 0 || u16_at(2)? != 1 || u16_at(4)? == 0 {
        return None;
    }
    let count = u16_at(4)?;
    let mut resources = Vec::new();
    let mut group = vec![0, 0, 1, 0]; // GRPICONDIR: reserved, type 1 = icon, count
    group.extend_from_slice(&count.to_le_bytes());
    for i in 0..usize::from(count) {
        let e = 6 + 16 * i;
        let size = u32_at(e + 8)? as usize;
        let offset = u32_at(e + 12)? as usize;
        let image = ico.get(offset..offset.checked_add(size)?)?;
        let id = u16::try_from(i + 1).ok()?;
        // MOVEABLE | DISCARDABLE, as rc.exe writes icons.
        resources.push(Resource {
            kind: RT_ICON,
            id,
            flags: 0x1010,
            data: image.to_vec(),
        });
        // GRPICONDIRENTRY: the ICO entry's first 12 bytes, then the RT_ICON id.
        group.extend_from_slice(ico.get(e..e + 12)?);
        group.extend_from_slice(&id.to_le_bytes());
    }
    resources.push(Resource {
        kind: RT_GROUP_ICON,
        id: 1,
        flags: 0x1030,
        data: group,
    });
    Some(resources)
}

fn put16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut Vec<u8>, v: usize) {
    b.extend_from_slice(&(v as u32).to_le_bytes());
}

fn pad(b: &mut Vec<u8>, to: usize) {
    b.resize(b.len().next_multiple_of(to), 0);
}

/// A `.res` file: an empty entry, then a RESOURCEHEADER + data per resource (ordinal type
/// and name, language neutral), each padded to 4 bytes.
fn res_file(resources: &[Resource]) -> Vec<u8> {
    let mut b = Vec::new();
    let empty = Resource {
        kind: 0,
        id: 0,
        flags: 0,
        data: Vec::new(),
    };
    for r in std::iter::once(&empty).chain(resources) {
        put32(&mut b, r.data.len()); // DataSize
        put32(&mut b, 32); // HeaderSize
        put16(&mut b, 0xffff);
        put16(&mut b, r.kind); // TYPE (ordinal)
        put16(&mut b, 0xffff);
        put16(&mut b, r.id); // NAME (ordinal)
        put32(&mut b, 0); // DataVersion
        put16(&mut b, r.flags); // MemoryFlags
        put16(&mut b, 0); // LanguageId: neutral
        put32(&mut b, 0); // Version
        put32(&mut b, 0); // Characteristics
        b.extend_from_slice(&r.data);
        pad(&mut b, 4);
    }
    b
}

/// A COFF object with one `.rsrc` section: the resource directory tree (type -> name ->
/// language), the data entries, then the data. Each data entry's address is an image-
/// relative relocation against the section, which the linker resolves.
/// `resources` must be sorted by (kind, id), as `icon_resources` returns them.
fn coff_object(resources: &[Resource], machine: u16, addr32nb: u16) -> Vec<u8> {
    let mut kinds: Vec<u16> = resources.iter().map(|r| r.kind).collect();
    kinds.dedup();
    let dir = |entries: usize| 16 + 8 * entries;
    // Layout: root, one name directory per type, one language directory per resource,
    // data entries, data.
    let names_at = dir(kinds.len());
    let mut langs_at = names_at;
    for k in &kinds {
        langs_at += dir(resources.iter().filter(|r| r.kind == *k).count());
    }
    let entries_at = langs_at + dir(1) * resources.len();
    let data_at = entries_at + 16 * resources.len();

    let mut s = Vec::new();
    let table = |s: &mut Vec<u8>, ids: usize| {
        s.extend_from_slice(&[0; 12]); // Characteristics, TimeDateStamp, Major/MinorVersion
        put16(s, 0); // named entries
        put16(s, ids as u16); // id entries
    };
    const SUBDIR: usize = 0x8000_0000;
    table(&mut s, kinds.len());
    let mut next = names_at;
    for k in &kinds {
        put32(&mut s, usize::from(*k));
        put32(&mut s, SUBDIR | next);
        next += dir(resources.iter().filter(|r| r.kind == *k).count());
    }
    let mut lang = langs_at;
    for k in &kinds {
        let of_kind: Vec<&Resource> = resources.iter().filter(|r| r.kind == *k).collect();
        table(&mut s, of_kind.len());
        for r in of_kind {
            put32(&mut s, usize::from(r.id));
            put32(&mut s, SUBDIR | lang);
            lang += dir(1);
        }
    }
    for i in 0..resources.len() {
        table(&mut s, 1);
        put32(&mut s, 0); // language neutral
        put32(&mut s, entries_at + 16 * i); // -> data entry
    }
    let mut relocs = Vec::new();
    let mut offset = data_at;
    for r in resources {
        relocs.push(s.len()); // OffsetToData: section offset + relocation
        put32(&mut s, offset);
        put32(&mut s, r.data.len());
        put32(&mut s, 0); // CodePage
        put32(&mut s, 0); // Reserved
        offset = (offset + r.data.len()).next_multiple_of(8);
    }
    for r in resources {
        s.extend_from_slice(&r.data);
        pad(&mut s, 8);
    }

    let raw_at = 20 + 40;
    let relocs_at = raw_at + s.len();
    let symbols_at = relocs_at + 10 * relocs.len();
    let mut o = Vec::new();
    put16(&mut o, machine);
    put16(&mut o, 1); // sections
    put32(&mut o, 0); // TimeDateStamp: reproducible
    put32(&mut o, symbols_at);
    put32(&mut o, 1); // symbols
    put16(&mut o, 0); // SizeOfOptionalHeader
    put16(&mut o, 0); // Characteristics
    o.extend_from_slice(b".rsrc\0\0\0");
    put32(&mut o, 0); // VirtualSize
    put32(&mut o, 0); // VirtualAddress
    put32(&mut o, s.len());
    put32(&mut o, raw_at);
    put32(&mut o, relocs_at);
    put32(&mut o, 0); // PointerToLinenumbers
    put16(&mut o, relocs.len() as u16);
    put16(&mut o, 0); // NumberOfLinenumbers
    put32(&mut o, 0x4030_0040); // INITIALIZED_DATA | ALIGN_4BYTES | MEM_READ
    o.extend_from_slice(&s);
    for at in relocs {
        put32(&mut o, at);
        put32(&mut o, 0); // symbol 0: the section
        put16(&mut o, addr32nb);
    }
    o.extend_from_slice(b".rsrc\0\0\0"); // symbol 0
    put32(&mut o, 0); // Value
    put16(&mut o, 1); // SectionNumber
    put16(&mut o, 0); // Type
    o.extend_from_slice(&[3, 0]); // StorageClass STATIC, no aux records
    put32(&mut o, 4); // empty string table
    o
}
